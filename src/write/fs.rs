//! File-system operations on a writable volume (spec: "File-System Objects", "Data Streams").
//! On-disk conventions (xfield order and flags, extent-reference records, uid/gid 99) follow what macOS
//! writes on external drives and what apfsck checks.

use super::Writer;
use super::tree::TreeId;
use crate::volume::{drec_hash_cmp, fold_name, names_match};
use crate::{bad, u16le, u32le, u64le};
use std::collections::BTreeMap;
use std::io;

const T_PHYS_EXT: u64 = 2;
const T_INODE: u64 = 3;
const T_XATTR: u64 = 4;
const T_DSTREAM_ID: u64 = 6;
const T_FILE_EXTENT: u64 = 8;
const T_DIR_REC: u64 = 9;
const OBJ_ID_MASK: u64 = 0x0fff_ffff_ffff_ffff;

const INO_NAME: u8 = 4;
const INO_DSTREAM: u8 = 8;
const INO_SPARSE_BYTES: u8 = 13;
const XF_DO_NOT_COPY: u8 = 0x02;
const XF_CHILDREN_INHERIT: u8 = 0x08;
const XF_SYSTEM_FIELD: u8 = 0x20;

const INODE_IS_SPARSE: u64 = 0x200;
const INODE_WAS_EVER_CLONED: u64 = 0x400;
const INODE_WAS_CLONED: u64 = 0x10;
const INODE_HAS_RSRC_FORK: u64 = 0x4000;
const INODE_NO_RSRC_FORK: u64 = 0x8000;
const INODE_HAS_UNCOMPRESSED_SIZE: u64 = 0x40000;
const UF_COMPRESSED: u32 = 0x20;
const XATTR_DATA_STREAM: u16 = 0x1;
const XATTR_DATA_EMBEDDED: u16 = 0x2;
const XATTR_FILE_SYSTEM_OWNED: u16 = 0x4;
const S_IFMT: u16 = 0o170000;
const S_IFDIR: u16 = 0o040000;
const S_IFREG: u16 = 0o100000;
const S_IFLNK: u16 = 0o120000;
/// uid/gid macOS gives files on external drives ("unknown"), so any Mac user can use them.
const UNKNOWN_ID: u32 = 99;
const APFS_KIND_NEW: u64 = 1;

/// What `create` makes.
pub enum Kind {
    File,
    Dir,
    Symlink(String),
}

pub(crate) fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos() as u64)
}

fn key(oid: u64, ty: u64) -> Vec<u8> {
    ((oid & OBJ_ID_MASK) | (ty << 60)).to_le_bytes().to_vec()
}

fn put64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

fn put32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// CRC-32C (Castagnoli), as used for directory-entry name hashes.
fn crc32c(mut crc: u32, data: &[u8]) -> u32 {
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0x82f6_3b78 } else { crc >> 1 };
        }
    }
    crc
}

/// Directory-entry hash (spec: j_drec_hashed_key_t): CRC-32C of the NFD (and, on case-insensitive
/// volumes, case-folded) name as UTF-32, low 22 bits.
pub(crate) fn name_hash(case_insensitive: bool, name: &str) -> u32 {
    let mut crc = 0xffff_ffff;
    for ch in fold_name(case_insensitive, name).chars() {
        crc = crc32c(crc, &(ch as u32).to_le_bytes());
    }
    crc & 0x3f_ffff
}

/// An inode record: the 92 fixed bytes plus its extended fields (type, flags, data), in disk order.
struct InodeRec {
    fixed: Vec<u8>,
    xf: Vec<(u8, u8, Vec<u8>)>,
}

impl InodeRec {
    fn parse(v: &[u8]) -> io::Result<InodeRec> {
        if v.len() < 92 {
            return Err(bad("inode record too short"));
        }
        let mut xf = vec![];
        if v.len() > 92 {
            let b = &v[92..];
            let n = u16le(b, 0) as usize;
            let mut data = 4 + 4 * n;
            for i in 0..n {
                let (ty, flags, size) = (b[4 + 4 * i], b[5 + 4 * i], u16le(b, 6 + 4 * i) as usize);
                xf.push((ty, flags, crate::slice(b, data, size)?.to_vec()));
                data += size.div_ceil(8) * 8;
            }
        }
        Ok(InodeRec { fixed: v[..92].to_vec(), xf })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.fixed.clone();
        if self.xf.is_empty() {
            return out;
        }
        let used: usize = self.xf.iter().map(|x| x.2.len().div_ceil(8) * 8).sum();
        out.extend((self.xf.len() as u16).to_le_bytes());
        out.extend((used as u16).to_le_bytes());
        for (ty, flags, data) in &self.xf {
            out.extend([*ty, *flags]);
            out.extend((data.len() as u16).to_le_bytes());
        }
        for (_, _, data) in &self.xf {
            out.extend(data);
            out.resize(out.len() + data.len().div_ceil(8) * 8 - data.len(), 0);
        }
        out
    }

    fn get(&self, ty: u8) -> Option<&Vec<u8>> {
        self.xf.iter().find(|x| x.0 == ty).map(|x| &x.2)
    }

    fn set(&mut self, ty: u8, flags: u8, data: Vec<u8>) {
        match self.xf.iter_mut().find(|x| x.0 == ty) {
            Some(x) => x.2 = data,
            None => self.xf.push((ty, flags, data)),
        }
    }

    fn remove(&mut self, ty: u8) {
        self.xf.retain(|x| x.0 != ty);
    }

    fn u64(&self, off: usize) -> u64 {
        u64le(&self.fixed, off)
    }
    fn set_u64(&mut self, off: usize, v: u64) {
        put64(&mut self.fixed, off, v);
    }
    fn mode(&self) -> u16 {
        u16le(&self.fixed, 80)
    }
    fn nlink(&self) -> i32 {
        u32le(&self.fixed, 56) as i32
    }
    fn set_nlink(&mut self, n: i32) {
        put32(&mut self.fixed, 56, n as u32);
    }
    fn touch(&mut self, t: u64) {
        self.set_u64(24, t); // mod_time
        self.set_u64(32, t); // change_time
    }
}

/// A file extent: `len` bytes of the file starting at `logical`, stored at block `phys` (0 = hole).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Ext {
    logical: u64,
    len: u64,
    phys: u64,
}

/// Directory entry found by `find_entry`.
pub(crate) struct Entry {
    key: Vec<u8>,
    val: Vec<u8>,
    pub id: u64,
}

impl Writer {
    fn writable(&self, v: usize) -> io::Result<()> {
        match &self.vols[v].read_only {
            Some(why) => Err(io::Error::new(io::ErrorKind::ReadOnlyFilesystem, why.clone())),
            None => Ok(()),
        }
    }

    fn ci(&self, v: usize) -> bool {
        u64le(&self.vols[v].sb, 56) & 0x1 != 0
    }

    fn inode_rec(&self, v: usize, id: u64) -> io::Result<InodeRec> {
        let val = self
            .tree_get(TreeId::Fs(v), &key(id, T_INODE))?
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("inode {id} not found")))?;
        InodeRec::parse(&val)
    }

    fn put_inode(&mut self, v: usize, id: u64, rec: &InodeRec) -> io::Result<()> {
        self.tree_put(TreeId::Fs(v), &key(id, T_INODE), &rec.to_bytes()).map(|_| ())
    }

    fn drec_key(&self, v: usize, parent: u64, name: &str) -> Vec<u8> {
        let mut k = key(parent, T_DIR_REC);
        let len = name.len() as u32 + 1;
        k.extend((len | name_hash(self.ci(v), name) << 10).to_le_bytes());
        k.extend(name.as_bytes());
        k.push(0);
        k
    }

    /// Finds `name` in directory `parent`, honoring the volume's case and normalization rules.
    pub(crate) fn find_entry(&self, v: usize, parent: u64, name: &str) -> io::Result<Option<Entry>> {
        let ci = self.ci(v);
        let hash = name_hash(ci, name);
        let mut found = None;
        self.view(v)?.scan(&|k: &[u8]| drec_hash_cmp(k, parent, hash), &mut |k, val| {
            let stored = String::from_utf8_lossy(&k[12..k.len().saturating_sub(1)]);
            if stored == name || names_match(ci, &stored, name) {
                found = Some(Entry { key: k.to_vec(), val: val.to_vec(), id: u64le(val, 0) });
                return Ok(false);
            }
            Ok(true)
        })?;
        Ok(found)
    }

    /// Creates a file, directory or symlink named `name` in directory `parent`. Returns its inode id.
    pub fn create(&mut self, v: usize, parent: u64, name: &str, kind: Kind, perm: u16) -> io::Result<u64> {
        self.writable(v)?;
        if name.is_empty() || name.len() > 255 || name.contains(['/', '\0']) || name == "." || name == ".." {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("invalid file name {name:?}")));
        }
        let mut p = self.inode_rec(v, parent)?;
        if p.mode() & S_IFMT != S_IFDIR {
            return Err(io::Error::new(io::ErrorKind::NotADirectory, "parent is not a directory"));
        }
        if self.find_entry(v, parent, name)?.is_some() {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, format!("{name:?} already exists")));
        }
        let ino = u64le(&self.vols[v].sb, 176);
        self.vol_add(v, 176, 1); // apfs_next_obj_id
        let now = now();
        let (mode, dtype, counter) = match &kind {
            Kind::File => (S_IFREG | (perm & 0o7777), 8u16, 184),
            Kind::Dir => (S_IFDIR | (perm & 0o7777), 4, 192),
            Kind::Symlink(_) => (S_IFLNK | 0o755, 10, 200),
        };
        let mut fixed = vec![0u8; 92];
        put64(&mut fixed, 0, parent);
        put64(&mut fixed, 8, ino); // private_id
        for off in [16, 24, 32, 40] {
            put64(&mut fixed, off, now);
        }
        put64(&mut fixed, 48, INODE_NO_RSRC_FORK);
        put32(&mut fixed, 56, if matches!(kind, Kind::Dir) { 0 } else { 1 });
        put32(&mut fixed, 72, UNKNOWN_ID);
        put32(&mut fixed, 76, UNKNOWN_ID);
        fixed[80..82].copy_from_slice(&mode.to_le_bytes());
        let mut name0 = name.as_bytes().to_vec();
        name0.push(0);
        let rec = InodeRec { fixed, xf: vec![(INO_NAME, XF_DO_NOT_COPY, name0)] };
        self.put_inode(v, ino, &rec)?;

        let mut dval = vec![0u8; 18];
        put64(&mut dval, 0, ino);
        put64(&mut dval, 8, now);
        dval[16..18].copy_from_slice(&dtype.to_le_bytes());
        let dkey = self.drec_key(v, parent, name);
        self.tree_put(TreeId::Fs(v), &dkey, &dval)?;

        if let Kind::Symlink(target) = &kind {
            let mut t = target.as_bytes().to_vec();
            t.push(0);
            self.put_xattr(v, ino, "com.apple.fs.symlink", XATTR_DATA_EMBEDDED | XATTR_FILE_SYSTEM_OWNED, &t)?;
        }

        p.set_nlink(p.nlink() + 1); // nchildren for directories
        p.touch(now);
        self.put_inode(v, parent, &p)?;
        self.vol_add(v, counter, 1);
        Ok(ino)
    }

    fn put_xattr(&mut self, v: usize, ino: u64, name: &str, flags: u16, data: &[u8]) -> io::Result<()> {
        let mut k = key(ino, T_XATTR);
        k.extend((name.len() as u16 + 1).to_le_bytes());
        k.extend(name.as_bytes());
        k.push(0);
        let mut val = flags.to_le_bytes().to_vec();
        val.extend((data.len() as u16).to_le_bytes());
        val.extend(data);
        self.tree_put(TreeId::Fs(v), &k, &val).map(|_| ())
    }

    fn xattr_key(ino: u64, name: &str) -> Vec<u8> {
        let mut k = key(ino, T_XATTR);
        k.extend((name.len() as u16 + 1).to_le_bytes());
        k.extend(name.as_bytes());
        k.push(0);
        k
    }

    /// Removes an xattr, freeing its data stream if it has one.
    fn remove_xattr(&mut self, v: usize, ino: u64, name: &str) -> io::Result<()> {
        if let Some(val) = self.tree_del(TreeId::Fs(v), &Self::xattr_key(ino, name))?
            && u16le(&val, 0) & XATTR_DATA_STREAM != 0
            && val.len() >= 12
        {
            let stream = u64le(&val, 4);
            let exts = self.extents(v, stream)?;
            self.sync_extents(v, stream, &exts, &[])?;
        }
        Ok(())
    }

    fn extents(&self, v: usize, dstream: u64) -> io::Result<Vec<Ext>> {
        let mut out = vec![];
        self.view(v)?.records(dstream, T_FILE_EXTENT as u8, &mut |k, val| {
            out.push(Ext { logical: u64le(k, 8), len: u64le(val, 0) & 0x00ff_ffff_ffff_ffff, phys: u64le(val, 8) });
            Ok(true)
        })?;
        Ok(out)
    }

    /// Rewrites a data stream's extent records (and extent-reference records) from `old` to `new`,
    /// freeing blocks that are no longer used.
    fn sync_extents(&mut self, v: usize, dstream: u64, old: &[Ext], new: &[Ext]) -> io::Result<()> {
        let fkey = |l: u64| {
            let mut k = key(dstream, T_FILE_EXTENT);
            k.extend(l.to_le_bytes());
            k
        };
        let old_l: BTreeMap<u64, &Ext> = old.iter().map(|e| (e.logical, e)).collect();
        let new_l: BTreeMap<u64, &Ext> = new.iter().map(|e| (e.logical, e)).collect();
        for l in old_l.keys().filter(|l| !new_l.contains_key(l)) {
            self.tree_del(TreeId::Fs(v), &fkey(*l))?;
        }
        for (l, e) in &new_l {
            if old_l.get(l) != Some(e) {
                let mut val = vec![0u8; 24];
                put64(&mut val, 0, e.len);
                put64(&mut val, 8, e.phys);
                self.tree_put(TreeId::Fs(v), &fkey(*l), &val)?;
            }
        }
        let bs = self.c.block_size;
        let phys = |list: &[Ext]| -> BTreeMap<u64, u64> {
            list.iter().filter(|e| e.phys != 0).map(|e| (e.phys, e.len / bs)).collect()
        };
        let (old_p, new_p) = (phys(old), phys(new));
        for p in old_p.keys().filter(|p| !new_p.contains_key(p)) {
            self.tree_del(TreeId::ExtentRef(v), &key(*p, T_PHYS_EXT))?;
        }
        for (p, n) in &new_p {
            if old_p.get(p) != Some(n) {
                let mut val = vec![0u8; 20];
                put64(&mut val, 0, n | APFS_KIND_NEW << 60);
                put64(&mut val, 8, dstream);
                put32(&mut val, 16, 1);
                self.tree_put(TreeId::ExtentRef(v), &key(*p, T_PHYS_EXT), &val)?;
            }
        }
        // Free blocks covered by old ranges but not new ones.
        for (&p, &n) in &old_p {
            let mut gaps = vec![(p, p + n)];
            for (&q, &m) in new_p.range(..p + n) {
                let (qs, qe) = (q, q + m);
                gaps = gaps
                    .into_iter()
                    .flat_map(
                        |(s, e)| {
                            if qe <= s || qs >= e { vec![(s, e)] } else { vec![(s, qs.max(s)), (qe.min(e), e)] }
                        },
                    )
                    .filter(|(s, e)| s < e)
                    .collect();
            }
            for (s, e) in gaps {
                self.free(Some(v), s, e - s)?;
            }
        }
        Ok(())
    }

    /// Opens a regular file's data for modification: undoes compression, returns its record and extents.
    fn data_rec(&mut self, v: usize, ino: u64) -> io::Result<(InodeRec, Vec<Ext>)> {
        self.writable(v)?;
        let mut rec = self.inode_rec(v, ino)?;
        if rec.mode() & S_IFMT != S_IFREG {
            return Err(io::Error::new(io::ErrorKind::IsADirectory, "not a regular file"));
        }
        if rec.u64(48) & (INODE_WAS_CLONED | INODE_WAS_EVER_CLONED) != 0 {
            // shortcut: cloned files share blocks; writing them needs block-level copy-on-write.
            return Err(io::Error::new(io::ErrorKind::Unsupported, "writing cloned files isn't supported yet"));
        }
        if u32le(&rec.fixed, 68) & UF_COMPRESSED != 0 {
            let data = {
                let view = self.view(v)?;
                let inode = view.inode(ino)?;
                view.open(&inode)?.read_all()?
            };
            self.remove_xattr(v, ino, "com.apple.decmpfs")?;
            self.remove_xattr(v, ino, "com.apple.ResourceFork")?;
            rec = self.inode_rec(v, ino)?;
            let bsd = u32le(&rec.fixed, 68) & !UF_COMPRESSED;
            put32(&mut rec.fixed, 68, bsd);
            let flags = rec.u64(48) & !(INODE_HAS_UNCOMPRESSED_SIZE | INODE_HAS_RSRC_FORK) | INODE_NO_RSRC_FORK;
            rec.set_u64(48, flags);
            rec.set_u64(84, 0);
            let private = rec.u64(8);
            let exts = self.extents(v, private)?;
            self.sync_extents(v, private, &exts, &[])?;
            self.set_dstream(&mut rec, |d| {
                put64(d, 0, 0);
                put64(d, 8, 0);
            });
            self.put_inode(v, ino, &rec)?;
            self.write_at(v, ino, 0, &data)?;
            rec = self.inode_rec(v, ino)?;
        }
        let exts = self.extents(v, rec.u64(8))?;
        Ok((rec, exts))
    }

    /// Edits the data-stream xfield, creating it (and the stream's reference record) if missing.
    fn set_dstream(&self, rec: &mut InodeRec, f: impl FnOnce(&mut [u8])) {
        let mut d = rec.get(INO_DSTREAM).cloned().unwrap_or_else(|| vec![0u8; 40]);
        f(&mut d);
        rec.set(INO_DSTREAM, XF_SYSTEM_FIELD, d);
    }

    fn ensure_dstream(&mut self, v: usize, rec: &mut InodeRec) -> io::Result<()> {
        if rec.get(INO_DSTREAM).is_none() {
            self.set_dstream(rec, |_| {});
            self.tree_put(TreeId::Fs(v), &key(rec.u64(8), T_DSTREAM_ID), &1u32.to_le_bytes())?;
        }
        Ok(())
    }

    /// Stores the extent list, sizes and sparse accounting after a data change.
    fn finish_data(
        &mut self,
        v: usize,
        ino: u64,
        mut rec: InodeRec,
        old: &[Ext],
        new: Vec<Ext>,
        size: u64,
    ) -> io::Result<()> {
        let new = merge(new, self.c.block_size);
        let private = rec.u64(8);
        self.sync_extents(v, private, old, &new)?;
        let alloced: u64 = new.iter().map(|e| e.len).sum();
        let sparse: u64 = new.iter().filter(|e| e.phys == 0).map(|e| e.len).sum();
        self.ensure_dstream(v, &mut rec)?;
        self.set_dstream(&mut rec, |d| {
            put64(d, 0, size);
            put64(d, 8, alloced);
        });
        let flags = rec.u64(48);
        if sparse > 0 {
            rec.set(INO_SPARSE_BYTES, XF_SYSTEM_FIELD | XF_CHILDREN_INHERIT, sparse.to_le_bytes().to_vec());
            rec.set_u64(48, flags | INODE_IS_SPARSE);
        } else {
            rec.remove(INO_SPARSE_BYTES);
            rec.set_u64(48, flags & !INODE_IS_SPARSE);
        }
        rec.touch(now());
        self.put_inode(v, ino, &rec)
    }

    /// Writes `data` at byte `off` of regular file `ino`, growing it as needed.
    pub fn write_at(&mut self, v: usize, ino: u64, off: u64, data: &[u8]) -> io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let (rec, old) = self.data_rec(v, ino)?;
        let bs = self.c.block_size;
        let size = rec.get(INO_DSTREAM).map_or(0, |d| u64le(d, 0));
        let end = off + data.len() as u64;
        let mut exts = old.clone();
        if end > size {
            self.zero_tail(v, &mut exts, size)?;
        }
        // Cover the write range with extents, then give holes inside it real blocks.
        let (b0, b1) = (off / bs * bs, end.div_ceil(bs) * bs);
        let alloced = exts.last().map_or(0, |e| e.logical + e.len);
        if b1 > alloced {
            exts.push(Ext { logical: alloced, len: b1 - alloced, phys: 0 });
        }
        split_at(&mut exts, b0, bs);
        split_at(&mut exts, b1, bs);
        let mut i = 0;
        while i < exts.len() {
            let e = exts[i];
            if e.phys == 0 && e.logical >= b0 && e.logical + e.len <= b1 {
                let (start, n) = self.alloc(Some(v), e.len / bs)?;
                let got = n * bs;
                exts[i] = Ext { logical: e.logical, len: got, phys: start };
                if got < e.len {
                    exts.insert(i + 1, Ext { logical: e.logical + got, len: e.len - got, phys: 0 });
                }
                // Fresh blocks: fill the parts outside the write with zeros.
                let mut buf = vec![0u8; got as usize];
                copy_overlap(&mut buf, e.logical, off, data);
                self.c.dev.write_at(start * bs, &buf)?;
            } else if e.phys != 0 && e.logical < end && e.logical + e.len > off {
                self.overwrite(e, off, data)?;
            }
            i += 1;
        }
        self.finish_data(v, ino, rec, &old, exts, size.max(end))
    }

    /// In-place write into an existing extent; partial blocks are read, patched and written back.
    fn overwrite(&mut self, e: Ext, off: u64, data: &[u8]) -> io::Result<()> {
        let bs = self.c.block_size;
        let end = off + data.len() as u64;
        let (s, t) = (off.max(e.logical) / bs * bs, end.min(e.logical + e.len).div_ceil(bs) * bs);
        let mut buf = vec![0u8; (t - s) as usize];
        let dev_off = e.phys * bs + (s - e.logical);
        if s < off || t > end {
            self.c.dev.read_at(dev_off, &mut buf)?;
        }
        copy_overlap(&mut buf, s, off, data);
        self.c.dev.write_at(dev_off, &buf)
    }

    /// Zeroes the bytes after `size` in its last block, so growing the file never exposes stale data.
    /// The block is copied rather than zeroed in place: until commit, the old block may still hold
    /// committed bytes (after an uncommitted shrink).
    fn zero_tail(&mut self, v: usize, exts: &mut Vec<Ext>, size: u64) -> io::Result<()> {
        let bs = self.c.block_size;
        if size.is_multiple_of(bs) {
            return Ok(());
        }
        let blk = size / bs * bs;
        if !exts.iter().any(|e| e.phys != 0 && e.logical <= blk && blk < e.logical + e.len) {
            return Ok(());
        }
        split_at(exts, blk, bs);
        split_at(exts, blk + bs, bs);
        let e = exts.iter_mut().find(|e| e.logical == blk).expect("split made this extent");
        let mut buf = vec![0u8; bs as usize];
        self.c.dev.read_at(e.phys * bs, &mut buf)?;
        buf[(size % bs) as usize..].fill(0);
        let (new, _) = self.alloc(Some(v), 1)?;
        self.c.dev.write_at(new * bs, &buf)?;
        exts.iter_mut().find(|e| e.logical == blk).unwrap().phys = new;
        Ok(())
    }

    /// Sets a regular file's size. Growing adds a hole; shrinking frees the blocks past the end.
    pub fn set_size(&mut self, v: usize, ino: u64, new_size: u64) -> io::Result<()> {
        let (rec, old) = self.data_rec(v, ino)?;
        let bs = self.c.block_size;
        let size = rec.get(INO_DSTREAM).map_or(0, |d| u64le(d, 0));
        if new_size == size {
            return Ok(());
        }
        let mut exts = old.clone();
        let want = new_size.div_ceil(bs) * bs;
        if new_size > size {
            self.zero_tail(v, &mut exts, size)?;
            let alloced = exts.last().map_or(0, |e| e.logical + e.len);
            if want > alloced {
                exts.push(Ext { logical: alloced, len: want - alloced, phys: 0 });
            }
        } else {
            // Bytes past the new end stay until the file grows again; growing zeroes them (zero_tail).
            split_at(&mut exts, want, bs);
            exts.retain(|e| e.logical < want);
        }
        self.finish_data(v, ino, rec, &old, exts, new_size)
    }

    /// Removes the entry `name` from `parent`; deletes the inode when its last link goes.
    pub fn remove(&mut self, v: usize, parent: u64, name: &str) -> io::Result<()> {
        self.writable(v)?;
        let e = self
            .find_entry(v, parent, name)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("{name:?} not found")))?;
        let rec = self.inode_rec(v, e.id)?;
        let is_dir = rec.mode() & S_IFMT == S_IFDIR;
        if is_dir && rec.nlink() != 0 {
            return Err(io::Error::new(io::ErrorKind::DirectoryNotEmpty, format!("{name:?} is not empty")));
        }
        if !is_dir && rec.nlink() > 1 {
            // shortcut: hard links need sibling records kept in sync; refuse rather than corrupt them.
            return Err(io::Error::new(io::ErrorKind::Unsupported, "removing hard-linked files isn't supported yet"));
        }
        self.tree_del(TreeId::Fs(v), &e.key)?;
        self.delete_inode(v, e.id, &rec)?;
        let mut p = self.inode_rec(v, parent)?;
        p.set_nlink(p.nlink() - 1);
        p.touch(now());
        self.put_inode(v, parent, &p)?;
        let counter = match rec.mode() & S_IFMT {
            S_IFDIR => 192,
            S_IFREG => 184,
            S_IFLNK => 200,
            _ => 208,
        };
        self.vol_add(v, counter, -1);
        Ok(())
    }

    fn delete_inode(&mut self, v: usize, id: u64, rec: &InodeRec) -> io::Result<()> {
        let mut xattrs = vec![];
        self.view(v)?.records(id, T_XATTR as u8, &mut |k, _| {
            xattrs.push(String::from_utf8_lossy(&k[10..k.len() - 1]).into_owned());
            Ok(true)
        })?;
        for name in xattrs {
            self.remove_xattr(v, id, &name)?;
        }
        let private = rec.u64(8);
        let exts = self.extents(v, private)?;
        self.sync_extents(v, private, &exts, &[])?;
        self.tree_del(TreeId::Fs(v), &key(private, T_DSTREAM_ID))?;
        self.tree_del(TreeId::Fs(v), &key(id, T_INODE))?;
        Ok(())
    }

    /// Moves/renames an entry. An existing target is replaced only if `replace` (directories must be empty).
    pub fn rename(
        &mut self,
        v: usize,
        parent: u64,
        name: &str,
        new_parent: u64,
        new_name: &str,
        replace: bool,
    ) -> io::Result<()> {
        self.writable(v)?;
        if new_name.is_empty() || new_name.len() > 255 || new_name.contains(['/', '\0']) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("invalid file name {new_name:?}")));
        }
        let src = self
            .find_entry(v, parent, name)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("{name:?} not found")))?;
        if let Some(dst) = self.find_entry(v, new_parent, new_name)?
            && dst.id != src.id
        {
            if !replace {
                return Err(io::Error::new(io::ErrorKind::AlreadyExists, format!("{new_name:?} already exists")));
            }
            let (s, d) = (self.inode_rec(v, src.id)?, self.inode_rec(v, dst.id)?);
            if (s.mode() & S_IFMT == S_IFDIR) != (d.mode() & S_IFMT == S_IFDIR) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "can't replace a file with a directory or back",
                ));
            }
            self.remove(v, new_parent, new_name)?;
        }
        let mut rec = self.inode_rec(v, src.id)?;
        if rec.mode() & S_IFMT == S_IFDIR && self.is_ancestor(v, src.id, new_parent)? {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "can't move a directory into itself"));
        }
        let now = now();
        self.tree_del(TreeId::Fs(v), &src.key)?;
        let dkey = self.drec_key(v, new_parent, new_name);
        self.tree_put(TreeId::Fs(v), &dkey, &src.val)?;
        rec.set_u64(0, new_parent);
        let mut name0 = new_name.as_bytes().to_vec();
        name0.push(0);
        rec.set(INO_NAME, XF_DO_NOT_COPY, name0);
        rec.set_u64(32, now);
        self.put_inode(v, src.id, &rec)?;
        let mut p = self.inode_rec(v, parent)?;
        p.touch(now);
        if parent != new_parent {
            p.set_nlink(p.nlink() - 1);
            self.put_inode(v, parent, &p)?;
            let mut np = self.inode_rec(v, new_parent)?;
            np.set_nlink(np.nlink() + 1);
            np.touch(now);
            self.put_inode(v, new_parent, &np)?;
        } else {
            self.put_inode(v, parent, &p)?;
        }
        Ok(())
    }

    /// True if directory `dir` is `id` or one of its ancestors chain contains `id`.
    fn is_ancestor(&self, v: usize, id: u64, mut dir: u64) -> io::Result<bool> {
        for _ in 0..4096 {
            if dir == id {
                return Ok(true);
            }
            if dir <= crate::volume::ROOT_DIR_INO {
                return Ok(false);
            }
            dir = self.inode_rec(v, dir)?.u64(0);
        }
        Err(bad("directory parent chain too long"))
    }

    /// Sets timestamps (nanoseconds since 1970); `None` leaves one unchanged.
    pub fn set_times(
        &mut self,
        v: usize,
        ino: u64,
        create: Option<u64>,
        modify: Option<u64>,
        change: Option<u64>,
        access: Option<u64>,
    ) -> io::Result<()> {
        self.writable(v)?;
        let mut rec = self.inode_rec(v, ino)?;
        for (off, t) in [(16, create), (24, modify), (32, change), (40, access)] {
            if let Some(t) = t {
                rec.set_u64(off, t);
            }
        }
        self.put_inode(v, ino, &rec)
    }

    /// Sets the permission bits (the file type bits are kept).
    pub fn set_mode(&mut self, v: usize, ino: u64, perm: u16) -> io::Result<()> {
        self.writable(v)?;
        let mut rec = self.inode_rec(v, ino)?;
        let mode = rec.mode() & S_IFMT | perm & 0o7777;
        rec.fixed[80..82].copy_from_slice(&mode.to_le_bytes());
        rec.set_u64(32, now());
        self.put_inode(v, ino, &rec)
    }

    /// Sets BSD flags (e.g. UF_HIDDEN 0x8000), preserving the compression flag.
    pub fn set_bsd_flags(&mut self, v: usize, ino: u64, flags: u32) -> io::Result<()> {
        self.writable(v)?;
        let mut rec = self.inode_rec(v, ino)?;
        let keep = u32le(&rec.fixed, 68) & UF_COMPRESSED;
        put32(&mut rec.fixed, 68, flags & !UF_COMPRESSED | keep);
        rec.set_u64(32, now());
        self.put_inode(v, ino, &rec)
    }
}

/// Splits the extent containing byte `at` (block aligned) so an extent starts exactly there.
fn split_at(exts: &mut Vec<Ext>, at: u64, bs: u64) {
    if let Some(i) = exts.iter().position(|e| e.logical < at && at < e.logical + e.len) {
        let e = exts[i];
        let head = at - e.logical;
        exts[i].len = head;
        exts.insert(
            i + 1,
            Ext { logical: at, len: e.len - head, phys: if e.phys == 0 { 0 } else { e.phys + head / bs } },
        );
    }
}

/// Joins neighbors that are both holes or physically contiguous.
fn merge(exts: Vec<Ext>, bs: u64) -> Vec<Ext> {
    let mut out: Vec<Ext> = vec![];
    for e in exts.into_iter().filter(|e| e.len > 0) {
        if let Some(last) = out.last_mut()
            && ((last.phys == 0 && e.phys == 0) || (last.phys != 0 && last.phys + last.len / bs == e.phys))
        {
            last.len += e.len;
            continue;
        }
        out.push(e);
    }
    out
}

/// Copies the part of `data` (which starts at file offset `data_off`) that overlaps `buf`
/// (which starts at file offset `buf_off`).
fn copy_overlap(buf: &mut [u8], buf_off: u64, data_off: u64, data: &[u8]) {
    let s = buf_off.max(data_off);
    let e = (buf_off + buf.len() as u64).min(data_off + data.len() as u64);
    if s < e {
        buf[(s - buf_off) as usize..(e - buf_off) as usize]
            .copy_from_slice(&data[(s - data_off) as usize..(e - data_off) as usize]);
    }
}
