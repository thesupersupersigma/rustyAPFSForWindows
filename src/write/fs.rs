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
const PEXT_LEN_MASK: u64 = 0x0fff_ffff_ffff_ffff;
const T_SIBLING_LINK: u64 = 5;
const T_SIBLING_MAP: u64 = 12;
const DREC_EXT_TYPE_SIBLING_ID: u8 = 1;
const INODE_MAINTAIN_DIR_STATS: u64 = 0x2;
const INODE_DIR_STATS_ORIGIN: u64 = 0x4;
const INO_DIR_STATS: u8 = 10;
const T_DIR_STATS: u64 = 10;

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
    fn do_create(&mut self, v: usize, parent: u64, name: &str, kind: Kind, perm: u16) -> io::Result<u64> {
        self.writable(v)?;
        check_name(name)?;
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
        let mut rec = InodeRec { fixed, xf: vec![(INO_NAME, XF_DO_NOT_COPY, name0)] };
        if let (Kind::Dir, Some(stat)) = (&kind, dirstat_of(&p)) {
            rec.set_u64(48, rec.u64(48) | INODE_MAINTAIN_DIR_STATS);
            rec.set(INO_DIR_STATS, XF_SYSTEM_FIELD | XF_DO_NOT_COPY, stat.to_le_bytes().to_vec());
        }
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

        self.adjust_dir(v, &mut p, 1)?;
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

    /// Rewrites a data stream's extent records from `old` to `new`, then updates the extent-reference
    /// tree by block ranges: ranges no longer used lose a reference (and are freed at zero), new ranges
    /// gain records.
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
        let ranges = |list: &[Ext]| -> Vec<(u64, u64)> {
            list.iter().filter(|e| e.phys != 0).map(|e| (e.phys, e.phys + e.len / bs)).collect()
        };
        let (o, n) = (ranges(old), ranges(new));
        for (s, e) in subtract(&o, &n) {
            self.adjust_refs(v, s, e - s, -1)?;
        }
        for (s, e) in subtract(&n, &o) {
            self.acquire(v, dstream, s, e - s)?;
        }
        Ok(())
    }

    /// The physical-extent record covering block `phys`, as (start, blocks, raw value).
    fn pext_at(&self, v: usize, phys: u64) -> io::Result<Option<(u64, u64, Vec<u8>)>> {
        Ok(self.tree_floor(TreeId::ExtentRef(v), &key(phys, T_PHYS_EXT))?.and_then(|(k, val)| {
            let (start, len) = (u64le(&k, 0) & OBJ_ID_MASK, u64le(&val, 0) & PEXT_LEN_MASK);
            (u64le(&k, 0) >> 60 == T_PHYS_EXT && phys < start + len).then_some((start, len, val))
        }))
    }

    fn put_pext(&mut self, v: usize, start: u64, len: u64, template: &[u8], refcnt: u32) -> io::Result<()> {
        let mut val = template.to_vec();
        put64(&mut val, 0, len | (u64le(template, 0) & !PEXT_LEN_MASK));
        put32(&mut val, 16, refcnt);
        self.tree_put(TreeId::ExtentRef(v), &key(start, T_PHYS_EXT), &val).map(|_| ())
    }

    /// Adds `delta` to the reference count of blocks [s, s+n), splitting records at the range edges.
    /// Blocks whose count reaches zero are freed.
    fn adjust_refs(&mut self, v: usize, s: u64, n: u64, delta: i64) -> io::Result<()> {
        let end = s + n;
        let mut pos = s;
        while pos < end {
            let Some((rs, rlen, val)) = self.pext_at(v, pos)? else {
                // No record: the block was exclusively owned without bookkeeping; drop it on release.
                if delta < 0 {
                    self.free(Some(v), pos, 1)?;
                }
                pos += 1;
                continue;
            };
            let (re, oe) = (rs + rlen, end.min(rs + rlen));
            let refcnt = u32le(&val, 16) as i64;
            self.tree_del(TreeId::ExtentRef(v), &key(rs, T_PHYS_EXT))?;
            if rs < pos {
                self.put_pext(v, rs, pos - rs, &val, refcnt as u32)?;
            }
            if refcnt + delta > 0 {
                self.put_pext(v, pos, oe - pos, &val, (refcnt + delta) as u32)?;
            } else {
                self.free(Some(v), pos, oe - pos)?;
            }
            if oe < re {
                self.put_pext(v, oe, re - oe, &val, refcnt as u32)?;
            }
            pos = oe;
        }
        Ok(())
    }

    /// Records freshly allocated blocks [s, s+n) as owned by `dstream`, extending the previous
    /// record when it ends right there.
    fn acquire(&mut self, v: usize, dstream: u64, s: u64, n: u64) -> io::Result<()> {
        let mut val = vec![0u8; 20];
        put64(&mut val, 0, APFS_KIND_NEW << 60);
        put64(&mut val, 8, dstream);
        if let Some(prev) = s.checked_sub(1)
            && let Some((ps, plen, pval)) = self.pext_at(v, prev)?
            && ps + plen == s
            && pval == {
                let mut t = val.clone();
                put64(&mut t, 0, plen | APFS_KIND_NEW << 60);
                put32(&mut t, 16, 1);
                t
            }
        {
            return self.put_pext(v, ps, plen + n, &pval, 1);
        }
        self.put_pext(v, s, n, &val, 1)
    }

    /// True if any block of [s, s+n) is referenced more than once (shared with a clone).
    fn shared(&self, v: usize, s: u64, n: u64) -> io::Result<bool> {
        let mut pos = s;
        while pos < s + n {
            match self.pext_at(v, pos)? {
                Some((rs, rlen, val)) => {
                    if u32le(&val, 16) > 1 {
                        return Ok(true);
                    }
                    pos = rs + rlen;
                }
                None => pos += 1,
            }
        }
        Ok(false)
    }

    fn dstream_refs(&self, v: usize, dstream: u64) -> io::Result<u32> {
        Ok(self.tree_get(TreeId::Fs(v), &key(dstream, T_DSTREAM_ID))?.map_or(0, |r| u32le(&r, 0)))
    }

    /// Gives a cloned inode its own data stream: same blocks, one more reference each.
    fn unshare_dstream(&mut self, v: usize, ino: u64, rec: &mut InodeRec) -> io::Result<()> {
        let private = rec.u64(8);
        let refs = self.dstream_refs(v, private)?;
        if refs <= 1 {
            return Ok(());
        }
        let exts = self.extents(v, private)?;
        let new_id = if private != ino && self.dstream_refs(v, ino)? == 0 && self.extents(v, ino)?.is_empty() {
            ino
        } else {
            let id = u64le(&self.vols[v].sb, 176);
            self.vol_add(v, 176, 1);
            id
        };
        let bs = self.c.block_size;
        for e in &exts {
            let mut k = key(new_id, T_FILE_EXTENT);
            k.extend(e.logical.to_le_bytes());
            let mut val = vec![0u8; 24];
            put64(&mut val, 0, e.len);
            put64(&mut val, 8, e.phys);
            self.tree_put(TreeId::Fs(v), &k, &val)?;
            if e.phys != 0 {
                self.adjust_refs(v, e.phys, e.len / bs, 1)?;
            }
        }
        self.tree_put(TreeId::Fs(v), &key(new_id, T_DSTREAM_ID), &1u32.to_le_bytes())?;
        self.tree_put(TreeId::Fs(v), &key(private, T_DSTREAM_ID), &(refs - 1).to_le_bytes())?;
        rec.set_u64(8, new_id);
        self.put_inode(v, ino, rec)
    }

    /// Opens a regular file's data for modification: undoes compression, returns its record and extents.
    fn data_rec(&mut self, v: usize, ino: u64) -> io::Result<(InodeRec, Vec<Ext>)> {
        self.writable(v)?;
        let mut rec = self.inode_rec(v, ino)?;
        if rec.mode() & S_IFMT != S_IFREG {
            return Err(io::Error::new(io::ErrorKind::IsADirectory, "not a regular file"));
        }
        if rec.u64(48) & (INODE_WAS_CLONED | INODE_WAS_EVER_CLONED) != 0 {
            self.unshare_dstream(v, ino, &mut rec)?;
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
            self.do_write_at(v, ino, 0, &data)?;
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
        let before = self.size_owner(v, &rec)?;
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
        let after = self.size_owner(v, &rec)?;
        self.move_size(v, before, after)?;
        self.put_inode(v, ino, &rec)
    }

    /// Writes `data` at byte `off` of regular file `ino`, growing it as needed.
    fn do_write_at(&mut self, v: usize, ino: u64, off: u64, data: &[u8]) -> io::Result<()> {
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
        let cloned = rec.u64(48) & (INODE_WAS_CLONED | INODE_WAS_EVER_CLONED) != 0;
        let mut out = Vec::with_capacity(exts.len() + 2);
        for e in exts {
            let inside = e.logical >= b0 && e.logical + e.len <= b1;
            if inside && e.phys == 0 {
                // A hole: fresh blocks, zero outside the written bytes.
                let mut buf = vec![0u8; e.len as usize];
                copy_overlap(&mut buf, e.logical, off, data);
                out.extend(self.alloc_write(v, e.logical, &buf)?);
            } else if inside && cloned && self.shared(v, e.phys, e.len / bs)? {
                // Blocks shared with a clone: copy, patch, write elsewhere.
                let mut buf = vec![0u8; e.len as usize];
                self.c.dev.read_at(e.phys * bs, &mut buf)?;
                copy_overlap(&mut buf, e.logical, off, data);
                out.extend(self.alloc_write(v, e.logical, &buf)?);
            } else {
                if inside {
                    self.overwrite(e, off, data)?;
                }
                out.push(e);
            }
        }
        self.finish_data(v, ino, rec, &old, out, size.max(end))
    }

    /// Writes `buf` (whole blocks of file data starting at `logical`) to newly allocated blocks.
    fn alloc_write(&mut self, v: usize, logical: u64, buf: &[u8]) -> io::Result<Vec<Ext>> {
        let bs = self.c.block_size;
        let mut out = vec![];
        let mut done = 0u64;
        while done < buf.len() as u64 {
            let (start, n) = self.alloc(Some(v), (buf.len() as u64 - done) / bs)?;
            let len = n * bs;
            self.c.dev.write_at(start * bs, &buf[done as usize..(done + len) as usize])?;
            out.push(Ext { logical: logical + done, len, phys: start });
            done += len;
        }
        Ok(out)
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
    fn do_set_size(&mut self, v: usize, ino: u64, new_size: u64) -> io::Result<()> {
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
    fn do_remove(&mut self, v: usize, parent: u64, name: &str) -> io::Result<()> {
        self.writable(v)?;
        let e = self
            .find_entry(v, parent, name)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("{name:?} not found")))?;
        let mut rec = self.inode_rec(v, e.id)?;
        let is_dir = rec.mode() & S_IFMT == S_IFDIR;
        if is_dir && rec.nlink() != 0 {
            return Err(io::Error::new(io::ErrorKind::DirectoryNotEmpty, format!("{name:?} is not empty")));
        }
        let before = self.size_owner(v, &rec)?;
        self.tree_del(TreeId::Fs(v), &e.key)?;
        if let Some(sib) = sibling_of(&e.val) {
            self.tree_del(TreeId::Fs(v), &sibling_key(e.id, sib))?;
            self.tree_del(TreeId::Fs(v), &key(sib, T_SIBLING_MAP))?;
        }
        let links = if is_dir { 1 } else { rec.nlink() };
        if links > 1 {
            // Other hard links remain: drop this one and make the lowest remaining sibling primary.
            rec.set_nlink(links - 1);
            if let Some((_, parent_id, name)) = self.siblings(v, e.id)?.into_iter().next() {
                rec.set_u64(0, parent_id);
                rec.set(INO_NAME, XF_DO_NOT_COPY, cstr0(&name));
            }
            rec.set_u64(32, now());
            self.put_inode(v, e.id, &rec)?;
            let after = self.size_owner(v, &rec)?;
            self.move_size(v, before, after)?;
            let mut p = self.inode_rec(v, parent)?;
            self.adjust_dir(v, &mut p, -1)?;
            p.touch(now());
            return self.put_inode(v, parent, &p);
        }
        self.move_size(v, before, None)?;
        self.delete_inode(v, e.id, &rec)?;
        let mut p = self.inode_rec(v, parent)?;
        self.adjust_dir(v, &mut p, -1)?;
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
        let refs = self.dstream_refs(v, private)?;
        if refs > 1 {
            // A clone still uses this data stream.
            self.tree_put(TreeId::Fs(v), &key(private, T_DSTREAM_ID), &(refs - 1).to_le_bytes())?;
        } else {
            let exts = self.extents(v, private)?;
            self.sync_extents(v, private, &exts, &[])?;
            self.tree_del(TreeId::Fs(v), &key(private, T_DSTREAM_ID))?;
        }
        for (sib, _, _) in self.siblings(v, id)? {
            self.tree_del(TreeId::Fs(v), &sibling_key(id, sib))?;
            self.tree_del(TreeId::Fs(v), &key(sib, T_SIBLING_MAP))?;
        }
        self.tree_del(TreeId::Fs(v), &key(id, T_INODE))?;
        Ok(())
    }

    /// Hard-link siblings of an inode: (sibling id, parent, name), lowest id (the primary link) first.
    fn siblings(&self, v: usize, ino: u64) -> io::Result<Vec<(u64, u64, String)>> {
        let mut out = vec![];
        self.view(v)?.records(ino, T_SIBLING_LINK as u8, &mut |k, val| {
            let name_len = u16le(val, 8) as usize;
            let name = String::from_utf8_lossy(&val[10..10 + name_len.saturating_sub(1)]).into_owned();
            out.push((u64le(k, 8), u64le(val, 0), name));
            Ok(true)
        })?;
        Ok(out)
    }

    fn put_sibling(&mut self, v: usize, ino: u64, sib: u64, parent: u64, name: &str) -> io::Result<()> {
        let mut val = parent.to_le_bytes().to_vec();
        val.extend((name.len() as u16 + 1).to_le_bytes());
        val.extend(cstr0(name));
        self.tree_put(TreeId::Fs(v), &sibling_key(ino, sib), &val)?;
        self.tree_put(TreeId::Fs(v), &key(sib, T_SIBLING_MAP), &ino.to_le_bytes()).map(|_| ())
    }

    fn new_obj_id(&mut self, v: usize) -> u64 {
        let id = u64le(&self.vols[v].sb, 176);
        self.vol_add(v, 176, 1);
        id
    }

    /// Adds a hard link `new_parent/new_name` to the existing file `ino`.
    fn do_link(&mut self, v: usize, ino: u64, new_parent: u64, new_name: &str) -> io::Result<()> {
        self.writable(v)?;
        check_name(new_name)?;
        let mut rec = self.inode_rec(v, ino)?;
        if rec.mode() & S_IFMT == S_IFDIR {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "can't hard-link a directory"));
        }
        if self.find_entry(v, new_parent, new_name)?.is_some() {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, format!("{new_name:?} already exists")));
        }
        // The first extra link gives the existing one a sibling record too.
        if self.siblings(v, ino)?.is_empty() {
            let (parent, name) = (rec.u64(0), cstr_of(rec.get(INO_NAME).map_or(&[][..], |n| n)));
            let e = self.find_entry(v, parent, &name)?.ok_or_else(|| bad("primary link not found"))?;
            let sib = self.new_obj_id(v);
            self.tree_put(TreeId::Fs(v), &e.key, &with_sibling(&e.val, sib))?;
            self.put_sibling(v, ino, sib, parent, &name)?;
        }
        let sib = self.new_obj_id(v);
        self.put_sibling(v, ino, sib, new_parent, new_name)?;
        let mut dval = vec![0u8; 18];
        put64(&mut dval, 0, ino);
        put64(&mut dval, 8, now());
        let dtype = if rec.mode() & S_IFMT == S_IFLNK { 10u16 } else { 8 };
        dval[16..18].copy_from_slice(&dtype.to_le_bytes());
        let dkey = self.drec_key(v, new_parent, new_name);
        self.tree_put(TreeId::Fs(v), &dkey, &with_sibling(&dval, sib))?;
        rec.set_nlink(rec.nlink() + 1);
        rec.set_u64(32, now());
        self.put_inode(v, ino, &rec)?;
        let mut p = self.inode_rec(v, new_parent)?;
        self.adjust_dir(v, &mut p, 1)?;
        p.touch(now());
        self.put_inode(v, new_parent, &p)
    }

    /// APFS clone: a new file sharing `src`'s data blocks until either side is written.
    fn do_clone_file(&mut self, v: usize, src: u64, parent: u64, name: &str) -> io::Result<u64> {
        let mut s = self.inode_rec(v, src)?;
        if s.mode() & S_IFMT != S_IFREG {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "only regular files can be cloned"));
        }
        if u32le(&s.fixed, 68) & UF_COMPRESSED != 0 {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "cloning compressed files isn't supported"));
        }
        let ino = self.do_create(v, parent, name, Kind::File, s.mode() & 0o7777)?;
        let Some(ds) = s.get(INO_DSTREAM).cloned() else { return Ok(ino) };
        let private = s.u64(8);
        let refs = self.dstream_refs(v, private)?;
        self.tree_put(TreeId::Fs(v), &key(private, T_DSTREAM_ID), &(refs + 1).to_le_bytes())?;
        let flags = INODE_WAS_CLONED | INODE_WAS_EVER_CLONED;
        let mut c = self.inode_rec(v, ino)?;
        c.set_u64(8, private);
        c.set_u64(48, c.u64(48) | flags);
        c.set(INO_DSTREAM, XF_SYSTEM_FIELD, ds);
        if let Some(sp) = s.get(INO_SPARSE_BYTES).cloned() {
            c.set(INO_SPARSE_BYTES, XF_SYSTEM_FIELD | XF_CHILDREN_INHERIT, sp);
            c.set_u64(48, c.u64(48) | INODE_IS_SPARSE);
        }
        self.put_inode(v, ino, &c)?;
        let owner = self.size_owner(v, &c)?;
        self.move_size(v, None, owner)?;
        s.set_u64(48, s.u64(48) | flags);
        self.put_inode(v, src, &s)?;
        Ok(ino)
    }

    /// Moves/renames an entry. An existing target is replaced only if `replace` (directories must be empty).
    fn do_rename(
        &mut self,
        v: usize,
        parent: u64,
        name: &str,
        new_parent: u64,
        new_name: &str,
        replace: bool,
    ) -> io::Result<()> {
        self.writable(v)?;
        check_name(new_name)?;
        let src = self
            .find_entry(v, parent, name)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("{name:?} not found")))?;
        let dst = self.find_entry(v, new_parent, new_name)?;
        if let Some(d) = &dst
            && d.id == src.id
            && d.key != src.key
        {
            return Ok(()); // both names are links to the same file: POSIX says do nothing
        }
        if let Some(dst) = dst
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
            self.do_remove(v, new_parent, new_name)?;
        }
        let mut rec = self.inode_rec(v, src.id)?;
        if rec.mode() & S_IFMT == S_IFDIR && self.is_ancestor(v, src.id, new_parent)? {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "can't move a directory into itself"));
        }
        if rec.mode() & S_IFMT == S_IFDIR
            && parent != new_parent
            && dirstat_of(&self.inode_rec(v, parent)?) != dirstat_of(&self.inode_rec(v, new_parent)?)
        {
            // shortcut: would need rewriting the whole subtree's statistics membership.
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "moving a folder into or out of a folder that tracks its size isn't supported",
            ));
        }
        let before = self.size_owner(v, &rec)?;
        let now = now();
        self.tree_del(TreeId::Fs(v), &src.key)?;
        let dkey = self.drec_key(v, new_parent, new_name);
        self.tree_put(TreeId::Fs(v), &dkey, &src.val)?;
        // The inode carries the primary link's name and parent; other hard links only their sibling record.
        let primary = match sibling_of(&src.val) {
            Some(sib) => {
                self.put_sibling(v, src.id, sib, new_parent, new_name)?;
                self.siblings(v, src.id)?.first().is_some_and(|f| f.0 == sib)
            }
            None => true,
        };
        if primary {
            rec.set_u64(0, new_parent);
            rec.set(INO_NAME, XF_DO_NOT_COPY, cstr0(new_name));
        }
        rec.set_u64(32, now);
        self.put_inode(v, src.id, &rec)?;
        let after = self.size_owner(v, &rec)?;
        self.move_size(v, before, after)?;
        let mut p = self.inode_rec(v, parent)?;
        p.touch(now);
        if parent != new_parent {
            self.adjust_dir(v, &mut p, -1)?;
            self.put_inode(v, parent, &p)?;
            let mut np = self.inode_rec(v, new_parent)?;
            self.adjust_dir(v, &mut np, 1)?;
            np.touch(now);
            self.put_inode(v, new_parent, &np)?;
        } else {
            self.put_inode(v, parent, &p)?;
        }
        Ok(())
    }

    /// Changes a directory's child count, and its directory statistics if it keeps them.
    fn adjust_dir(&mut self, v: usize, dir: &mut InodeRec, children: i32) -> io::Result<()> {
        dir.set_nlink(dir.nlink() + children);
        match dirstat_of(dir) {
            Some(stat) => self.stat_add(v, stat, children as i64, 0),
            None => Ok(()),
        }
    }

    fn stat_add(&mut self, v: usize, stat: u64, children: i64, size: i64) -> io::Result<()> {
        let k = key(stat, T_DIR_STATS);
        let Some(mut val) = self.tree_get(TreeId::Fs(v), &k)? else { return Ok(()) };
        let (n, total, gen_count) =
            (u64le(&val, 0) as i64 + children, u64le(&val, 8) as i64 + size, u64le(&val, 24) + 1);
        put64(&mut val, 0, n as u64);
        put64(&mut val, 8, total as u64);
        put64(&mut val, 24, gen_count);
        self.tree_put(TreeId::Fs(v), &k, &val).map(|_| ())
    }

    /// The directory statistics a regular file's size counts toward (its primary parent's), and the size.
    fn size_owner(&self, v: usize, rec: &InodeRec) -> io::Result<Option<(u64, u64)>> {
        let parent = rec.u64(0);
        if rec.mode() & S_IFMT != S_IFREG || parent <= crate::volume::ROOT_DIR_INO && parent != 2 {
            return Ok(None);
        }
        let size = rec.get(INO_DSTREAM).map_or(0, |d| u64le(d, 0));
        Ok(dirstat_of(&self.inode_rec(v, parent)?).map(|s| (s, size)))
    }

    fn move_size(&mut self, v: usize, before: Option<(u64, u64)>, after: Option<(u64, u64)>) -> io::Result<()> {
        if before == after {
            return Ok(());
        }
        if let Some((s, n)) = before {
            self.stat_add(v, s, 0, -(n as i64))?;
        }
        if let Some((s, n)) = after {
            self.stat_add(v, s, 0, n as i64)?;
        }
        Ok(())
    }

    /// Turns on size tracking ("directory statistics") for an empty directory, as macOS can.
    fn do_enable_dir_stats(&mut self, v: usize, dir: u64) -> io::Result<()> {
        self.writable(v)?;
        let mut rec = self.inode_rec(v, dir)?;
        if rec.mode() & S_IFMT != S_IFDIR || rec.nlink() != 0 || dirstat_of(&rec).is_some() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "needs an empty directory without stats"));
        }
        let stat = self.new_obj_id(v);
        self.tree_put(TreeId::Fs(v), &key(stat, T_DIR_STATS), &[0u8; 32])?;
        rec.set_u64(48, rec.u64(48) | INODE_MAINTAIN_DIR_STATS | INODE_DIR_STATS_ORIGIN);
        rec.set(INO_DIR_STATS, XF_SYSTEM_FIELD | XF_DO_NOT_COPY, stat.to_le_bytes().to_vec());
        self.put_inode(v, dir, &rec)
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
    fn do_set_times(
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
    fn do_set_mode(&mut self, v: usize, ino: u64, perm: u16) -> io::Result<()> {
        self.writable(v)?;
        let mut rec = self.inode_rec(v, ino)?;
        let mode = rec.mode() & S_IFMT | perm & 0o7777;
        rec.fixed[80..82].copy_from_slice(&mode.to_le_bytes());
        rec.set_u64(32, now());
        self.put_inode(v, ino, &rec)
    }

    /// Sets BSD flags (e.g. UF_HIDDEN 0x8000), preserving the compression flag.
    fn do_set_bsd_flags(&mut self, v: usize, ino: u64, flags: u32) -> io::Result<()> {
        self.writable(v)?;
        let mut rec = self.inode_rec(v, ino)?;
        let keep = u32le(&rec.fixed, 68) & UF_COMPRESSED;
        put32(&mut rec.fixed, 68, flags & !UF_COMPRESSED | keep);
        rec.set_u64(32, now());
        self.put_inode(v, ino, &rec)
    }
}

/// The directory-statistics object a directory contributes to, if it maintains statistics.
fn dirstat_of(rec: &InodeRec) -> Option<u64> {
    if rec.u64(48) & INODE_MAINTAIN_DIR_STATS == 0 {
        return None;
    }
    rec.get(INO_DIR_STATS).filter(|d| d.len() >= 8).map(|d| u64le(d, 0))
}

fn check_name(name: &str) -> io::Result<()> {
    if name.is_empty() || name.len() > 255 || name.contains(['/', '\0']) || name == "." || name == ".." {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("invalid file name {name:?}")));
    }
    Ok(())
}

fn cstr0(name: &str) -> Vec<u8> {
    let mut b = name.as_bytes().to_vec();
    b.push(0);
    b
}

fn cstr_of(b: &[u8]) -> String {
    String::from_utf8_lossy(&b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]).into_owned()
}

fn sibling_key(ino: u64, sib: u64) -> Vec<u8> {
    let mut k = key(ino, T_SIBLING_LINK);
    k.extend(sib.to_le_bytes());
    k
}

/// The sibling id stored in a directory entry's xfield, if it is a hard link.
fn sibling_of(drec_val: &[u8]) -> Option<u64> {
    (drec_val.len() >= 34 && drec_val[22] == DREC_EXT_TYPE_SIBLING_ID).then(|| u64le(drec_val, 26))
}

/// A directory-entry value carrying a sibling-id xfield.
fn with_sibling(drec_val: &[u8], sib: u64) -> Vec<u8> {
    let mut v = drec_val[..18].to_vec();
    v.extend(1u16.to_le_bytes()); // one xfield
    v.extend(8u16.to_le_bytes()); // 8 bytes of xfield data
    v.extend([DREC_EXT_TYPE_SIBLING_ID, XF_DO_NOT_COPY]);
    v.extend(8u16.to_le_bytes());
    v.extend(sib.to_le_bytes());
    v
}

/// Parts of the ranges in `a` not covered by any range in `b` (half-open block ranges).
fn subtract(a: &[(u64, u64)], b: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut out = vec![];
    for &(s, e) in a {
        let mut parts = vec![(s, e)];
        for &(bs, be) in b {
            parts = parts
                .into_iter()
                .flat_map(|(s, e)| if be <= s || bs >= e { vec![(s, e)] } else { vec![(s, bs.max(s)), (be.min(e), e)] })
                .filter(|(s, e)| s < e)
                .collect();
        }
        out.extend(parts);
    }
    out
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

/// Public operations. Each runs atomically: if it fails after it started changing things, every
/// uncommitted change is dropped (as if the program had stopped right after the last commit).
impl Writer {
    /// Creates a file, directory or symlink named `name` in directory `parent`. Returns its inode id.
    pub fn create(&mut self, v: usize, parent: u64, name: &str, kind: Kind, perm: u16) -> io::Result<u64> {
        self.atomic(SMALL, |w| w.do_create(v, parent, name, kind, perm))
    }

    /// Writes `data` at byte `off` of regular file `ino`, growing it as needed.
    pub fn write_at(&mut self, v: usize, ino: u64, off: u64, data: &[u8]) -> io::Result<()> {
        let blocks = (data.len() as u64).div_ceil(self.c.block_size) + 1;
        self.atomic(SMALL + blocks, |w| w.do_write_at(v, ino, off, data))
    }

    /// Sets a regular file's size. Growing adds a hole; shrinking frees the blocks past the end.
    pub fn set_size(&mut self, v: usize, ino: u64, size: u64) -> io::Result<()> {
        self.atomic(TINY, |w| w.do_set_size(v, ino, size))
    }

    /// Removes the entry `name` from `parent`; deletes the inode when its last link goes.
    pub fn remove(&mut self, v: usize, parent: u64, name: &str) -> io::Result<()> {
        self.atomic(TINY, |w| w.do_remove(v, parent, name))
    }

    /// Adds a hard link `new_parent/new_name` to the existing file `ino`.
    pub fn link(&mut self, v: usize, ino: u64, new_parent: u64, new_name: &str) -> io::Result<()> {
        self.atomic(SMALL, |w| w.do_link(v, ino, new_parent, new_name))
    }

    /// APFS clone: a new file sharing `src`'s data blocks until either side is written.
    pub fn clone_file(&mut self, v: usize, src: u64, parent: u64, name: &str) -> io::Result<u64> {
        self.atomic(SMALL, |w| w.do_clone_file(v, src, parent, name))
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
        self.atomic(SMALL, |w| w.do_rename(v, parent, name, new_parent, new_name, replace))
    }

    /// Turns on size tracking ("directory statistics") for an empty directory, as macOS can.
    #[doc(hidden)]
    pub fn enable_dir_stats(&mut self, v: usize, dir: u64) -> io::Result<()> {
        self.atomic(SMALL, |w| w.do_enable_dir_stats(v, dir))
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
        self.atomic(TINY, |w| w.do_set_times(v, ino, create, modify, change, access))
    }

    /// Sets the permission bits (the file type bits are kept).
    pub fn set_mode(&mut self, v: usize, ino: u64, perm: u16) -> io::Result<()> {
        self.atomic(TINY, |w| w.do_set_mode(v, ino, perm))
    }

    /// Sets BSD flags (e.g. UF_HIDDEN 0x8000), preserving the compression flag.
    pub fn set_bsd_flags(&mut self, v: usize, ino: u64, flags: u32) -> io::Result<()> {
        self.atomic(TINY, |w| w.do_set_bsd_flags(v, ino, flags))
    }
}

/// Free blocks an operation needs before it starts: metadata copy-on-write for the operation and the
/// next commit. Removals need less so a full disk can still be cleaned up.
const SMALL: u64 = 64;
const TINY: u64 = 16;
