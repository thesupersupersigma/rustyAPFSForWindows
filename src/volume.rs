//! Volumes and the file-system tree (spec: "Volumes", "File-System Objects", "Data Streams", "Snapshot Metadata").

use crate::container::{Container, OBJ_PHYSICAL, OBJECT_TYPE_FS};
use crate::crypto::{self, Xts};
use crate::{bad, btree, compress, slice, u16le, u32le, u64le};
use std::cmp::Ordering;
use std::io;
use std::sync::Arc;
use unicode_normalization::UnicodeNormalization;

mod dump;

const APFS_TYPE_SNAP_METADATA: u8 = 1;
const APFS_TYPE_INODE: u8 = 3;
const APFS_TYPE_XATTR: u8 = 4;
const APFS_TYPE_FILE_EXTENT: u8 = 8;
const APFS_TYPE_DIR_REC: u8 = 9;
const OBJ_ID_MASK: u64 = 0x0fff_ffff_ffff_ffff;

pub const ROOT_DIR_INO: u64 = 2;
const INCOMPAT_CASE_INSENSITIVE: u64 = 0x1;
const INCOMPAT_NORMALIZATION_INSENSITIVE: u64 = 0x8;
const APFS_FS_UNENCRYPTED: u64 = 0x1;
const APFS_FS_ONEKEY: u64 = 0x8;
const XATTR_DATA_STREAM: u16 = 0x1;
const XATTR_DATA_EMBEDDED: u16 = 0x2;
const INO_EXT_TYPE_DSTREAM: u8 = 8;
const INO_EXT_TYPE_RDEV: u8 = 14;
const UF_COMPRESSED: u32 = 0x20;
const S_IFMT: u16 = 0o170000;

pub struct Volume<'c> {
    c: &'c Container,
    pub superblock: Vec<u8>,
    pub name: String,
    pub incompatible_features: u64,
    /// Software-encrypted volumes encrypt their metadata and data; call `unlock` before reading.
    pub encrypted: bool,
    /// Transaction id this view reads at (a snapshot's xid for snapshot views).
    pub xid: u64,
    omap_tree: u64,
    root_tree: u64,
    physical_tree: bool,
    /// Volume encryption key, once unlocked.
    key: Option<Arc<Xts>>,
}

#[derive(Clone, Debug)]
pub struct Inode {
    pub id: u64,
    pub parent_id: u64,
    /// Id of this inode's data stream (its file extents are keyed by this).
    pub private_id: u64,
    /// Nanoseconds since 1970-01-01 UTC.
    pub create_time: u64,
    pub mod_time: u64,
    pub change_time: u64,
    pub access_time: u64,
    /// Number of children for directories, hard-link count for everything else.
    pub nchildren_or_nlink: i32,
    pub bsd_flags: u32,
    pub uid: u32,
    pub gid: u32,
    pub mode: u16,
    /// Logical size from the data-stream field; 0 when the inode has none. Compressed files report
    /// their real size through `File::size`.
    pub size: u64,
    pub rdev: Option<u32>,
}

impl Inode {
    pub fn is_dir(&self) -> bool {
        self.mode & S_IFMT == 0o040000
    }
    pub fn is_file(&self) -> bool {
        self.mode & S_IFMT == 0o100000
    }
    pub fn is_symlink(&self) -> bool {
        self.mode & S_IFMT == 0o120000
    }
    pub fn is_compressed(&self) -> bool {
        self.bsd_flags & UF_COMPRESSED != 0
    }
}

#[derive(Clone, Debug)]
pub struct DirEntry {
    pub name: String,
    pub id: u64,
    /// BSD `DT_*` type from the directory record (4 = dir, 8 = file, 10 = symlink, ...).
    pub kind: u8,
}

#[derive(Clone, Debug)]
pub struct Snapshot {
    pub name: String,
    pub xid: u64,
    pub create_time: u64,
    sblock: u64,
}

#[derive(Clone, Copy, Debug)]
struct Extent {
    logical: u64,
    len: u64,
    phys: u64,      // 0 = sparse
    crypto_id: u64, // ONEKEY volumes: tweak base in blocks (usually the original phys), so first sector = id * bs/512
}

/// An opened file's data. Compressed files are decompressed fully on open.
pub struct File<'c> {
    c: &'c Container,
    pub size: u64,
    data: Data,
    key: Option<Arc<Xts>>,
}

enum Data {
    Extents(Vec<Extent>),
    Memory(Vec<u8>),
}

impl<'c> Volume<'c> {
    /// A view at `xid` whose object map tree root is already known (used by the writer).
    pub(crate) fn with_root(c: &'c Container, sb: Vec<u8>, xid: u64, omap_tree: u64) -> io::Result<Volume<'c>> {
        Self::with_omap(c, sb, xid, Some(omap_tree), None)
    }

    pub(crate) fn new(c: &'c Container, sb: Vec<u8>, xid: u64) -> io::Result<Volume<'c>> {
        Self::with_omap(c, sb, xid, None, None)
    }

    fn with_omap(
        c: &'c Container,
        sb: Vec<u8>,
        xid: u64,
        omap_tree: Option<u64>,
        key: Option<Arc<Xts>>,
    ) -> io::Result<Volume<'c>> {
        if &sb[32..36] != b"APSB" {
            return Err(bad("volume superblock has no APSB magic"));
        }
        let name_bytes = &sb[704..960];
        let name =
            String::from_utf8_lossy(&name_bytes[..name_bytes.iter().position(|&b| b == 0).unwrap_or(256)]).into_owned();
        let incompatible_features = u64le(&sb, 56);
        let encrypted = u64le(&sb, 264) & APFS_FS_UNENCRYPTED == 0;
        let omap_tree = match omap_tree {
            Some(t) => t,
            None => c.omap_tree_of(u64le(&sb, 128))?,
        };
        let physical_tree = u32le(&sb, 116) & OBJ_PHYSICAL != 0;
        let root_oid = u64le(&sb, 136);
        // The object map itself is never encrypted, so the root can be found before unlocking.
        let root_tree = if physical_tree { root_oid } else { c.omap_lookup(omap_tree, root_oid, xid)? };
        Ok(Volume {
            c,
            superblock: sb,
            name,
            incompatible_features,
            encrypted,
            xid,
            omap_tree,
            root_tree,
            physical_tree,
            key,
        })
    }

    /// Unlocks a software-encrypted volume with a user password (no-op for unencrypted volumes).
    /// A wrong password fails with `ErrorKind::PermissionDenied`.
    pub fn unlock(&mut self, password: &str) -> io::Result<()> {
        if !self.encrypted || self.key.is_some() {
            return Ok(());
        }
        if u64le(&self.superblock, 264) & APFS_FS_ONEKEY == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "volume uses per-file encryption keys (hardware encryption), which isn't supported",
            ));
        }
        self.key = Some(Arc::new(crypto::unlock_volume(self.c, &self.superblock, password)?));
        Ok(())
    }

    pub fn is_locked(&self) -> bool {
        self.encrypted && self.key.is_none()
    }

    pub fn case_insensitive(&self) -> bool {
        self.incompatible_features & INCOMPAT_CASE_INSENSITIVE != 0
    }

    fn hashed_names(&self) -> bool {
        self.incompatible_features & (INCOMPAT_CASE_INSENSITIVE | INCOMPAT_NORMALIZATION_INSENSITIVE) != 0
    }

    /// Visits every file-system record of type `ty` for object `oid`, in key order.
    pub(crate) fn records(&self, oid: u64, ty: u8, visit: btree::Visit) -> io::Result<()> {
        if self.is_locked() {
            return Err(locked());
        }
        let resolve = |child: u64| {
            if self.physical_tree { Ok(child) } else { self.c.omap_lookup(self.omap_tree, child, self.xid) }
        };
        let cmp = |k: &[u8]| {
            if k.len() < 8 {
                return Ordering::Less; // malformed key: skip it rather than panic
            }
            let h = u64le(k, 0);
            (h & OBJ_ID_MASK).cmp(&oid).then(((h >> 60) as u8).cmp(&ty))
        };
        btree::walk_key(self.c, self.root_tree, &resolve, &cmp, visit, self.key.as_deref())
    }

    pub fn inode(&self, id: u64) -> io::Result<Inode> {
        let mut found = None;
        self.records(id, APFS_TYPE_INODE, &mut |_, v| {
            found = Some(parse_inode(id, v)?);
            Ok(false)
        })?;
        found.ok_or_else(|| not_found(format!("inode {id}")))
    }

    pub fn root(&self) -> io::Result<Inode> {
        self.inode(ROOT_DIR_INO)
    }

    pub fn read_dir(&self, id: u64) -> io::Result<Vec<DirEntry>> {
        let hashed = self.hashed_names();
        let mut out = vec![];
        self.records(id, APFS_TYPE_DIR_REC, &mut |k, v| {
            let name = if hashed {
                slice(k, 12, (u32le(slice(k, 8, 4)?, 0) & 0x3ff) as usize)?
            } else {
                slice(k, 10, u16le(slice(k, 8, 2)?, 0) as usize)?
            };
            let v = slice(v, 0, 18)?;
            out.push(DirEntry { name: cstr(name), id: u64le(v, 0), kind: (u16le(v, 16) & 0xf) as u8 });
            Ok(true)
        })?;
        Ok(out)
    }

    /// Looks up a `/`-separated path from the root directory. Symlinks are not followed.
    pub fn lookup(&self, path: &str) -> io::Result<Inode> {
        let mut id = ROOT_DIR_INO;
        for part in path.split('/').filter(|p| !p.is_empty()) {
            id = self.find_child(id, part)?.ok_or_else(|| not_found(path.to_string()))?;
        }
        self.inode(id)
    }

    /// Finds `name` in directory `dir` (case/normalization rules of the volume), returning its inode id.
    pub fn find_child(&self, dir: u64, name: &str) -> io::Result<Option<u64>> {
        let ci = self.case_insensitive();
        // Hashed volumes: only records with the name's hash can match. ASCII folding is unambiguous;
        // for other names also fall back to a scan in case Apple's case folding differs from ours.
        if self.hashed_names() {
            let hash = crate::write::name_hash(ci, name);
            let mut found = None;
            self.scan(&|k: &[u8]| drec_hash_cmp(k, dir, hash), &mut |k, v| {
                if names_match(ci, &cstr(&k[12..]), name) {
                    found = Some(u64le(slice(v, 0, 8)?, 0));
                    return Ok(false);
                }
                Ok(true)
            })?;
            if found.is_some() || name.is_ascii() {
                return Ok(found);
            }
        }
        Ok(self.read_dir(dir)?.into_iter().find(|e| names_match(ci, &e.name, name)).map(|e| e.id))
    }

    /// Visits file-system tree records in key order whose key `cmp` reports `Equal`.
    pub(crate) fn scan(&self, cmp: &dyn Fn(&[u8]) -> Ordering, visit: btree::Visit) -> io::Result<()> {
        if self.is_locked() {
            return Err(locked());
        }
        let resolve = |child: u64| {
            if self.physical_tree { Ok(child) } else { self.c.omap_lookup(self.omap_tree, child, self.xid) }
        };
        btree::walk_key(self.c, self.root_tree, &resolve, cmp, visit, self.key.as_deref())
    }

    pub fn xattr_names(&self, id: u64) -> io::Result<Vec<String>> {
        let mut out = vec![];
        self.records(id, APFS_TYPE_XATTR, &mut |k, _| {
            out.push(cstr(slice(k, 10, u16le(slice(k, 8, 2)?, 0) as usize)?));
            Ok(true)
        })?;
        Ok(out)
    }

    pub fn xattr(&self, id: u64, name: &str) -> io::Result<Option<Vec<u8>>> {
        let mut found = None;
        self.records(id, APFS_TYPE_XATTR, &mut |k, v| {
            if cstr(slice(k, 10, u16le(slice(k, 8, 2)?, 0) as usize)?) != name {
                return Ok(true);
            }
            let flags = u16le(slice(v, 0, 4)?, 0);
            found = Some(if flags & XATTR_DATA_EMBEDDED != 0 {
                slice(v, 4, u16le(v, 2) as usize)?.to_vec()
            } else if flags & XATTR_DATA_STREAM != 0 {
                let ds = slice(v, 4, 16)?; // j_xattr_dstream_t: obj id, then j_dstream_t whose first field is size
                self.file_from_stream(u64le(ds, 0), u64le(ds, 8))?.read_all()?
            } else {
                return Err(bad(format!("xattr {name} has neither embedded nor stream data")));
            });
            Ok(false)
        })?;
        Ok(found)
    }

    pub fn readlink(&self, inode: &Inode) -> io::Result<String> {
        let target = self.xattr(inode.id, "com.apple.fs.symlink")?.ok_or_else(|| bad("symlink without target"))?;
        Ok(cstr(&target))
    }

    fn file_from_stream(&self, dstream_id: u64, size: u64) -> io::Result<File<'c>> {
        let mut extents = vec![];
        self.records(dstream_id, APFS_TYPE_FILE_EXTENT, &mut |k, v| {
            let v = slice(v, 0, 24)?;
            extents.push(Extent {
                logical: u64le(slice(k, 8, 8)?, 0),
                len: u64le(v, 0) & 0x00ff_ffff_ffff_ffff,
                phys: u64le(v, 8),
                crypto_id: u64le(v, 16),
            });
            Ok(true)
        })?;
        Ok(File { c: self.c, size, data: Data::Extents(extents), key: self.key.clone() })
    }

    pub fn open(&self, inode: &Inode) -> io::Result<File<'c>> {
        if inode.is_compressed()
            && let Some(decmpfs) = self.xattr(inode.id, "com.apple.decmpfs")?
        {
            let rsrc = if compress::needs_resource_fork(&decmpfs) {
                self.xattr(inode.id, "com.apple.ResourceFork")?
            } else {
                None
            };
            let data = compress::decompress(&decmpfs, rsrc.as_deref())?;
            return Ok(File { c: self.c, size: data.len() as u64, data: Data::Memory(data), key: None });
        }
        self.file_from_stream(inode.private_id, inode.size)
    }

    pub fn snapshots(&self) -> io::Result<Vec<Snapshot>> {
        if self.is_locked() {
            return Err(locked());
        }
        let tree = u64le(&self.superblock, 152);
        if tree == 0 {
            return Ok(vec![]);
        }
        let physical = u32le(&self.superblock, 124) & OBJ_PHYSICAL != 0;
        let resolve =
            |child: u64| if physical { Ok(child) } else { self.c.omap_lookup(self.omap_tree, child, self.xid) };
        let root = resolve(tree)?;
        let mut out = vec![];
        // The tree also holds name-index records; keep only the metadata ones.
        let key = self.key.as_deref();
        btree::walk_key(
            self.c,
            root,
            &resolve,
            &|_| Ordering::Equal,
            &mut |k, v| {
                let h = u64le(slice(k, 0, 8)?, 0);
                if (h >> 60) as u8 == APFS_TYPE_SNAP_METADATA {
                    let name_len = u16le(slice(v, 48, 2)?, 0) as usize;
                    out.push(Snapshot {
                        name: cstr(slice(v, 50, name_len)?),
                        xid: h & OBJ_ID_MASK,
                        create_time: u64le(v, 16),
                        sblock: u64le(v, 8),
                    });
                }
                Ok(true)
            },
            key,
        )?;
        Ok(out)
    }

    /// A read-only view of the volume as it was when the snapshot was taken.
    pub fn snapshot(&self, s: &Snapshot) -> io::Result<Volume<'c>> {
        // Snapshot data is resolved through the live object map at the snapshot's xid.
        let sb = self.c.read_obj_key(s.sblock, OBJECT_TYPE_FS, self.key.as_deref())?;
        Volume::with_omap(self.c, sb, s.xid, Some(self.omap_tree), self.key.clone())
    }
}

impl File<'_> {
    /// Reads up to `buf.len()` bytes at `off`; returns the count (0 at end of file).
    pub fn read_at(&self, off: u64, buf: &mut [u8]) -> io::Result<usize> {
        if off >= self.size {
            return Ok(0);
        }
        let end = self.size.min(off + buf.len() as u64);
        let extents = match &self.data {
            Data::Memory(m) => {
                let n = (end - off) as usize;
                buf[..n].copy_from_slice(&m[off as usize..end as usize]);
                return Ok(n);
            }
            Data::Extents(e) => e,
        };
        let mut pos = off;
        while pos < end {
            let out = &mut buf[(pos - off) as usize..(end - off) as usize];
            let i = extents.partition_point(|e| e.logical <= pos);
            let hit = i.checked_sub(1).map(|i| extents[i]).filter(|e| pos < e.logical + e.len);
            let n = match hit {
                Some(e) => {
                    let n = out.len().min((e.logical + e.len - pos) as usize);
                    let rel = pos - e.logical;
                    if e.phys == 0 {
                        out[..n].fill(0);
                    } else if let Some(k) = &self.key {
                        // Decrypt whole 512-byte units; extents are block-sized, so they stay inside the extent.
                        let first = rel / 512;
                        let mut units = vec![0; ((rel + n as u64).div_ceil(512) - first) as usize * 512];
                        self.c.read_at(e.phys * self.c.block_size + first * 512, &mut units)?;
                        k.decrypt(&mut units, e.crypto_id * (self.c.block_size / 512) + first);
                        let skip = (rel % 512) as usize;
                        out[..n].copy_from_slice(&units[skip..skip + n]);
                    } else {
                        self.c.read_at(e.phys * self.c.block_size + rel, &mut out[..n])?;
                    }
                    n
                }
                None => {
                    // Gap before the next extent (or past the last one) reads as zeros.
                    let next = extents.get(i).map_or(end, |e| e.logical.min(end));
                    let n = out.len().min((next - pos) as usize);
                    out[..n].fill(0);
                    n
                }
            };
            pos += n as u64;
        }
        Ok((end - off) as usize)
    }

    pub fn read_all(&self) -> io::Result<Vec<u8>> {
        let mut buf = vec![0; usize::try_from(self.size).map_err(|_| bad("file too large for memory"))?];
        self.read_at(0, &mut buf)?;
        Ok(buf)
    }
}

fn parse_inode(id: u64, v: &[u8]) -> io::Result<Inode> {
    let v_fixed = slice(v, 0, 92)?;
    let mut ino = Inode {
        id,
        parent_id: u64le(v_fixed, 0),
        private_id: u64le(v_fixed, 8),
        create_time: u64le(v_fixed, 16),
        mod_time: u64le(v_fixed, 24),
        change_time: u64le(v_fixed, 32),
        access_time: u64le(v_fixed, 40),
        nchildren_or_nlink: u32le(v_fixed, 56) as i32,
        bsd_flags: u32le(v_fixed, 68),
        uid: u32le(v_fixed, 72),
        gid: u32le(v_fixed, 76),
        mode: u16le(v_fixed, 80),
        size: 0,
        rdev: None,
    };
    if v.len() > 92 {
        for (ty, data) in xfields(&v[92..])? {
            match ty {
                INO_EXT_TYPE_DSTREAM => ino.size = u64le(slice(data, 0, 8)?, 0),
                INO_EXT_TYPE_RDEV => ino.rdev = Some(u32le(slice(data, 0, 4)?, 0)),
                _ => {}
            }
        }
    }
    Ok(ino)
}

/// Splits an xf_blob_t into (type, data) pairs. Data entries are padded to 8 bytes.
fn xfields(b: &[u8]) -> io::Result<Vec<(u8, &[u8])>> {
    let n = u16le(slice(b, 0, 4)?, 0) as usize;
    let mut data_off = 4 + 4 * n;
    let mut out = vec![];
    for i in 0..n {
        let x = slice(b, 4 + 4 * i, 4)?;
        let size = u16le(x, 2) as usize;
        out.push((x[0], slice(b, data_off, size)?));
        data_off += (size + 7) & !7;
    }
    Ok(out)
}

/// Null-terminated UTF-8 from disk, lossily decoded.
fn cstr(b: &[u8]) -> String {
    String::from_utf8_lossy(&b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]).into_owned()
}

fn locked() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "volume is encrypted: unlock it with its password first")
}

/// Orders a file-system key against the directory records of `dir` with name hash `hash`.
pub(crate) fn drec_hash_cmp(k: &[u8], dir: u64, hash: u32) -> Ordering {
    if k.len() < 8 {
        return Ordering::Less; // malformed key: skip it rather than panic
    }
    let h = u64le(k, 0);
    // The record type lives in the top bits, but the tree sorts by object id first.
    (h & OBJ_ID_MASK, h >> 60)
        .cmp(&(dir, APFS_TYPE_DIR_REC as u64))
        .then_with(|| if k.len() < 12 { Ordering::Less } else { (u32le(k, 8) >> 10).cmp(&hash) })
}

/// The form names are compared (and hashed) in: NFD, and case-folded on case-insensitive volumes.
pub(crate) fn fold_name(case_insensitive: bool, name: &str) -> String {
    let nfd: String = name.nfd().collect();
    if case_insensitive { caseless::default_case_fold_str(&nfd).nfd().collect() } else { nfd }
}

/// Name equality as the volume sees it. Always normalization-insensitive: Windows typically sends
/// composed (NFC) names while macOS often stores decomposed (NFD) ones, even on volumes without the flag.
pub(crate) fn names_match(case_insensitive: bool, stored: &str, wanted: &str) -> bool {
    stored == wanted || fold_name(case_insensitive, stored) == fold_name(case_insensitive, wanted)
}

fn not_found(what: String) -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, format!("not found: {what}"))
}
