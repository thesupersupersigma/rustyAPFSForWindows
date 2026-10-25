//! Write support: copy-on-write transactions over a container.
//!
//! Changed metadata goes to the container's overlay (so reads see it at once) and reaches the disk at
//! `commit`, followed by a new checkpoint: ephemeral objects, checkpoint map, then the superblock.
//! New file data is written straight to freshly allocated blocks, which no checkpoint references yet.

mod fs;
mod spaceman;
mod tree;

pub use fs::Kind;
pub(crate) use fs::name_hash;

use crate::container::{Container, OBJECT_TYPE_FS, OBJECT_TYPE_OMAP, checksum_ok, fletcher64};
use crate::crypto::{self, Xts};
use crate::{Volume, bad, u32le, u64le};
use spaceman::{SFQ_IP, SFQ_MAIN, Spaceman};
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tree::TreeId;

const OBJECT_TYPE_SPACEMAN: u32 = 0x5;
const OBJECT_TYPE_CHECKPOINT_MAP: u32 = 0xc;
const OBJ_PHYSICAL: u32 = 0x4000_0000;
const NX_INCOMPAT_VERSION2: u64 = 0x2;
const APFS_FS_UNENCRYPTED: u64 = 0x1;
const APFS_FS_ONEKEY: u64 = 0x8;
const OMAP_VAL_ENCRYPTED: u32 = 0x4;
const INCOMPAT_CASE_INSENSITIVE: u64 = 0x1;
const INCOMPAT_NORMALIZATION_INSENSITIVE: u64 = 0x8;
const INCOMPAT_ENC_ROLLED: u64 = 0x4;
const INCOMPAT_SEALED_VOLUME: u64 = 0x20;
const INCOMPAT_INCOMPLETE_RESTORE: u64 = 0x10;
const MODIFIED_BY: &str = concat!("rusty-apfs ", env!("CARGO_PKG_VERSION"));

pub(crate) struct OmapState {
    phys: u64,
    phys_xid: u64,
    raw: Vec<u8>,
    pub(crate) tree: u64,
}

pub(crate) struct Vol {
    oid: u64,
    pub(crate) sb: Vec<u8>,
    sb_paddr: u64,
    sb_xid: u64,
    pub(crate) omap: OmapState,
    pub(crate) dirty: bool,
    /// Why the volume can't be written, if it can't (encryption aside: see `key`).
    pub read_only: Option<String>,
    touched: bool,
    /// Software-encrypted: file-system tree nodes and file data are encrypted with the volume key.
    pub(crate) encrypted: bool,
    pub(crate) key: Option<Arc<Xts>>,
    /// Kept to unlock again after a rollback reopens the device.
    password: Option<String>,
}

struct Ephemeral {
    oid: u64,
    ty: u32,
    subtype: u32,
    data: Vec<u8>,
}

/// A container opened for writing. Changes become durable at `commit`.
pub struct Writer {
    pub(crate) c: Container,
    pub(crate) txn: u64,
    pub(crate) nx: Vec<u8>,
    sm: Spaceman,
    sm_oid: u64,
    fq_roots: [Option<Vec<u8>>; 2],
    eph: Vec<Ephemeral>,
    pub(crate) nx_omap: OmapState,
    pub(crate) vols: Vec<Vol>,
    dirty: bool,
    /// Where we came from, to reload on rollback.
    path: PathBuf,
    partition: Option<usize>,
    /// Bumped by every in-memory state change; tells whether a failed operation changed anything.
    mutations: u64,
    /// Set when a rollback itself failed (e.g. the disk went away): everything is refused afterwards.
    poisoned: Option<String>,
}

/// Computes and stores an object's Fletcher-64 checksum.
pub(crate) fn seal(b: &mut [u8]) {
    let ck = fletcher64(&b[8..]);
    b[0..8].copy_from_slice(&ck.to_le_bytes());
}

fn unsupported(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, msg.into())
}

impl Writer {
    /// Opens an image, partition or GPT disk (see `Container::open`) for writing.
    pub fn open(path: impl AsRef<Path>, partition: Option<usize>) -> io::Result<Writer> {
        Self::from_container(Container::open_rw(path.as_ref(), partition)?, path.as_ref(), partition)
    }

    fn from_container(c: Container, path: &Path, partition: Option<usize>) -> io::Result<Writer> {
        let nx = c.superblock.clone();
        let bs = c.block_size;
        if u64le(&nx, 64) & !NX_INCOMPAT_VERSION2 != 0 {
            return Err(unsupported(format!("container features {:#x} can't be written (Fusion?)", u64le(&nx, 64))));
        }
        let (desc_blocks, data_blocks) = (u32le(&nx, 104), u32le(&nx, 108));
        if (desc_blocks | data_blocks) & 0x8000_0000 != 0 {
            return Err(unsupported("non-contiguous checkpoint areas can't be written"));
        }

        // Load every ephemeral object listed in the current checkpoint map.
        let (desc_base, data_base) = (u64le(&nx, 112), u64le(&nx, 120));
        let (didx, dlen) = (u32le(&nx, 136), u32le(&nx, 140));
        let mut eph_data: HashMap<u64, Vec<u8>> = HashMap::new();
        let mut eph = vec![];
        for k in 0..dlen.saturating_sub(1) {
            let b = c.read_block(desc_base + ((didx + k) % desc_blocks) as u64)?;
            if !checksum_ok(&b) || u32le(&b, 24) & 0xffff != OBJECT_TYPE_CHECKPOINT_MAP {
                return Err(bad("bad checkpoint map block"));
            }
            for m in 0..u32le(&b, 36) as usize {
                let o = 40 + 40 * m;
                let (ty, subtype, size, oid, paddr) =
                    (u32le(&b, o), u32le(&b, o + 4), u32le(&b, o + 8), u64le(&b, o + 24), u64le(&b, o + 32));
                // Big containers have a space manager spanning several blocks, stored contiguously.
                let n = size as u64 / bs;
                if n == 0 || !(size as u64).is_multiple_of(bs) {
                    return Err(bad(format!("ephemeral object {oid} has size {size}")));
                }
                if paddr < data_base || paddr + n > data_base + data_blocks as u64 {
                    return Err(bad("ephemeral object outside the checkpoint data area"));
                }
                let mut data = Vec::with_capacity(size as usize);
                for i in 0..n {
                    data.extend(c.read_block(paddr + i)?);
                }
                if !checksum_ok(&data) {
                    return Err(bad(format!("bad checksum on ephemeral object {oid}")));
                }
                eph_data.insert(oid, data.clone());
                eph.push(Ephemeral { oid, ty, subtype, data });
            }
        }
        let sm_oid = u64le(&nx, 152);
        let sm_raw = eph_data.get(&sm_oid).ok_or_else(|| bad("spaceman missing from checkpoint"))?.clone();
        let sm = Spaceman::load(&c, sm_raw, &eph_data)?;
        let fq_roots = [SFQ_IP, SFQ_MAIN].map(|q| eph_data.get(&u64le(&sm.raw, 200 + 40 * q + 8)).cloned());
        // Spaceman and free-queue nodes are rebuilt each checkpoint; everything else is carried over.
        eph.retain(|e| {
            let t = e.ty & 0xffff;
            t != OBJECT_TYPE_SPACEMAN && !((t == 2 || t == 3) && e.subtype == 9)
        });

        let load_omap = |phys: u64| -> io::Result<OmapState> {
            let raw = c.read_obj(phys, OBJECT_TYPE_OMAP)?;
            Ok(OmapState { phys, phys_xid: u64le(&raw, 16), tree: u64le(&raw, 48), raw })
        };
        let nx_omap = load_omap(u64le(&nx, 160))?;
        let mut vols = vec![];
        for i in 0..u32le(&nx, 180).min(100) as usize {
            let oid = u64le(&nx, 184 + 8 * i);
            if oid == 0 {
                continue;
            }
            let sb_paddr = c.omap_lookup(nx_omap.tree, oid, c.xid)?;
            let sb = c.read_obj(sb_paddr, OBJECT_TYPE_FS)?;
            let omap = load_omap(u64le(&sb, 128))?;
            let incompat = u64le(&sb, 56);
            let encrypted = u64le(&sb, 264) & APFS_FS_UNENCRYPTED == 0;
            let read_only = if encrypted && u64le(&sb, 264) & APFS_FS_ONEKEY == 0 {
                Some("volumes with per-file (hardware) encryption keys are read-only")
            } else if u64le(&sb, 216) != 0 {
                Some("volumes with snapshots are read-only")
            } else if incompat & (INCOMPAT_SEALED_VOLUME | INCOMPAT_INCOMPLETE_RESTORE) != 0 || u64le(&sb, 1024) != 0 {
                Some("sealed or partially restored volumes are read-only")
            } else if incompat & !(INCOMPAT_CASE_INSENSITIVE | INCOMPAT_ENC_ROLLED | INCOMPAT_NORMALIZATION_INSENSITIVE)
                != 0
            {
                Some("the volume uses features this writer doesn't know")
            } else if incompat & (INCOMPAT_CASE_INSENSITIVE | INCOMPAT_NORMALIZATION_INSENSITIVE) == 0 {
                Some("pre-release (beta) format volumes are read-only")
            } else if u32le(&sb, 116) & OBJ_PHYSICAL != 0 {
                Some("volumes with a physical file-system tree are read-only")
            } else {
                None
            };
            vols.push(Vol {
                oid,
                sb_xid: u64le(&sb, 16),
                sb,
                sb_paddr,
                omap,
                dirty: false,
                read_only: read_only.map(str::to_string),
                touched: false,
                encrypted,
                key: None,
                password: None,
            });
        }
        let txn = u64le(&nx, 96);
        let mut w = Writer {
            c,
            txn,
            nx,
            sm,
            sm_oid,
            fq_roots,
            eph,
            nx_omap,
            vols,
            dirty: false,
            path: path.to_path_buf(),
            partition,
            mutations: 0,
            poisoned: None,
        };
        w.sm.drain(&w.c, txn.saturating_sub(2), txn)?;
        Ok(w)
    }

    /// A read-only view of volume `v` including uncommitted changes. Don't keep it across writes.
    pub fn view(&self, v: usize) -> io::Result<Volume<'_>> {
        let vol = &self.vols[v];
        Volume::with_root(&self.c, vol.sb.clone(), self.txn, vol.omap.tree, vol.key.clone())
    }

    /// Unlocks a software-encrypted volume so it can be read and written (no-op otherwise).
    /// A wrong password fails with `ErrorKind::PermissionDenied`.
    pub fn unlock(&mut self, v: usize, password: &str) -> io::Result<()> {
        let vol = &self.vols[v];
        if !vol.encrypted || vol.key.is_some() {
            return Ok(());
        }
        if u64le(&vol.sb, 264) & APFS_FS_ONEKEY == 0 {
            return Err(unsupported("volume uses per-file encryption keys (hardware encryption)"));
        }
        let key = crypto::unlock_volume(&self.c, &vol.sb, password)?;
        let vol = &mut self.vols[v];
        vol.key = Some(Arc::new(key));
        vol.password = Some(password.to_string());
        Ok(())
    }

    pub fn is_locked(&self, v: usize) -> bool {
        self.vols[v].encrypted && self.vols[v].key.is_none()
    }

    pub fn volume_count(&self) -> usize {
        self.vols.len()
    }

    /// Why volume `v` can't be written, or None if it can.
    pub fn read_only_reason(&self, v: usize) -> Option<&str> {
        match self.vols[v].read_only.as_deref() {
            None if self.is_locked(v) => Some("the volume is encrypted and locked: unlock it with its password"),
            r => r,
        }
    }

    pub fn free_blocks(&self) -> u64 {
        self.sm.free_blocks()
    }

    pub fn block_size(&self) -> u64 {
        self.c.block_size
    }

    pub fn total_blocks(&self) -> u64 {
        u64le(&self.nx, 40)
    }

    pub fn has_changes(&self) -> bool {
        self.dirty
    }

    pub(crate) fn alloc_meta(&mut self, owner: Option<usize>) -> io::Result<u64> {
        Ok(self.alloc(owner, 1)?.0)
    }

    pub(crate) fn alloc(&mut self, owner: Option<usize>, want: u64) -> io::Result<(u64, u64)> {
        self.mutations += 1;
        let (start, n) = self.sm.alloc(&self.c, want, self.txn)?;
        self.dirty = true;
        if let Some(v) = owner {
            self.vol_add(v, 88, n as i64); // apfs_fs_alloc_count
            self.vol_add(v, 224, n as i64); // apfs_total_blocks_alloced
        }
        Ok((start, n))
    }

    pub(crate) fn free_meta(&mut self, owner: Option<usize>, paddr: u64) -> io::Result<()> {
        self.free(owner, paddr, 1)
    }

    pub(crate) fn free(&mut self, owner: Option<usize>, paddr: u64, n: u64) -> io::Result<()> {
        self.mutations += 1;
        self.sm.free(paddr, n, self.txn);
        self.dirty = true;
        if let Some(v) = owner {
            self.vol_add(v, 88, -(n as i64));
            self.vol_add(v, 232, n as i64); // apfs_total_blocks_freed
        }
        Ok(())
    }

    pub(crate) fn vol_add(&mut self, v: usize, off: usize, delta: i64) {
        self.mutations += 1;
        let sb = &mut self.vols[v].sb;
        let x = (u64le(sb, off) as i64 + delta) as u64;
        sb[off..off + 8].copy_from_slice(&x.to_le_bytes());
        self.vols[v].dirty = true;
        self.dirty = true;
    }

    /// Next container-wide virtual object id.
    pub(crate) fn next_oid(&mut self) -> u64 {
        self.mutations += 1;
        let oid = u64le(&self.nx, 88);
        self.nx[88..96].copy_from_slice(&(oid + 1).to_le_bytes());
        oid
    }

    fn omap_key(oid: u64, xid: u64) -> [u8; 16] {
        let mut k = [0u8; 16];
        k[..8].copy_from_slice(&oid.to_le_bytes());
        k[8..].copy_from_slice(&xid.to_le_bytes());
        k
    }

    fn omap_val(&self, paddr: u64) -> [u8; 16] {
        let mut v = [0u8; 16];
        v[4..8].copy_from_slice(&(self.c.block_size as u32).to_le_bytes());
        v[8..].copy_from_slice(&paddr.to_le_bytes());
        v
    }

    pub(crate) fn omap_map(&mut self, v: usize, oid: u64, paddr: u64) -> io::Result<()> {
        let mut val = self.omap_val(paddr);
        // Only file-system tree nodes are mapped here, and on encrypted volumes they are stored encrypted.
        if self.vols[v].encrypted {
            val[0..4].copy_from_slice(&OMAP_VAL_ENCRYPTED.to_le_bytes());
        }
        self.tree_put(TreeId::VolOmap(v), &Self::omap_key(oid, self.txn), &val).map(|_| ())
    }

    pub(crate) fn omap_unmap(&mut self, v: usize, oid: u64, xid: u64) -> io::Result<()> {
        self.tree_del(TreeId::VolOmap(v), &Self::omap_key(oid, xid)).map(|_| ())
    }

    /// Rewrites an object map's omap_phys (copy-on-write) after its tree root moved; returns its address.
    pub(crate) fn store_omap_phys(&mut self, vol: Option<usize>) -> io::Result<u64> {
        let (phys, phys_xid) = match vol {
            None => (self.nx_omap.phys, self.nx_omap.phys_xid),
            Some(v) => (self.vols[v].omap.phys, self.vols[v].omap.phys_xid),
        };
        let addr = if phys_xid != self.txn {
            let new = self.alloc_meta(vol)?;
            self.free_meta(vol, phys)?;
            new
        } else {
            phys
        };
        let txn = self.txn;
        let st = match vol {
            None => &mut self.nx_omap,
            Some(v) => &mut self.vols[v].omap,
        };
        st.phys = addr;
        st.phys_xid = txn;
        st.raw[8..16].copy_from_slice(&addr.to_le_bytes());
        st.raw[16..24].copy_from_slice(&txn.to_le_bytes());
        st.raw[48..56].copy_from_slice(&st.tree.to_le_bytes());
        seal(&mut st.raw);
        let raw = st.raw.clone();
        self.c.put_block(addr, raw);
        Ok(addr)
    }

    /// Makes all changes durable by writing a new checkpoint. If that fails, the uncommitted changes
    /// are dropped and the volume stays as of the previous commit.
    pub fn commit(&mut self) -> io::Result<()> {
        self.atomic(0, |w| w.do_commit())
    }

    /// Runs `f`; if it fails after changing state, rolls back to the last commit. Refuses to start when
    /// fewer than `need` blocks are free (so a full disk fails cleanly instead of half-way).
    pub(crate) fn atomic<T>(&mut self, need: u64, f: impl FnOnce(&mut Self) -> io::Result<T>) -> io::Result<T> {
        if let Some(why) = &self.poisoned {
            return Err(io::Error::other(format!("writer unusable after a failed rollback: {why}")));
        }
        // Freed blocks only return two commits later; when short of space, commit to reclaim them.
        for _ in 0..2 {
            if self.sm.free_blocks() >= need || self.sm.queued_main_blocks() == 0 {
                break;
            }
            self.dirty = true;
            if let Err(e) = self.do_commit() {
                self.rollback();
                return Err(e);
            }
        }
        if self.sm.free_blocks() < need {
            return Err(io::Error::new(io::ErrorKind::StorageFull, "APFS container is full"));
        }
        let before = self.mutations;
        let r = f(self);
        if r.is_err() && self.mutations != before {
            self.rollback();
        }
        r
    }

    /// Drops every uncommitted change by reloading from disk, exactly like reopening after a crash.
    fn rollback(&mut self) {
        let passwords: Vec<_> = self.vols.iter().map(|v| v.password.clone()).collect();
        // Reopen through our own handle: the exclusive-writer lock would refuse a second open.
        let reopened = self.c.reopen().and_then(|c| Writer::from_container(c, &self.path, self.partition));
        let reopened = reopened.and_then(|mut fresh| {
            for (v, pw) in passwords.iter().enumerate() {
                if let Some(pw) = pw {
                    fresh.unlock(v, pw)?;
                }
            }
            Ok(fresh)
        });
        match reopened {
            Ok(fresh) => *self = fresh,
            Err(e) => self.poisoned = Some(e.to_string()),
        }
    }

    fn do_commit(&mut self) -> io::Result<()> {
        if !self.dirty {
            return Ok(());
        }
        let txn = self.txn;
        let bs = self.c.block_size as usize;
        let now = fs::now();

        // Volume superblocks are virtual objects mapped by the container omap.
        for v in 0..self.vols.len() {
            if !self.vols[v].dirty {
                continue;
            }
            if self.vols[v].sb_xid != txn {
                let (oid, old, old_xid) = (self.vols[v].oid, self.vols[v].sb_paddr, self.vols[v].sb_xid);
                let new = self.alloc_meta(Some(v))?;
                self.free_meta(Some(v), old)?;
                self.tree_del(TreeId::NxOmap, &Self::omap_key(oid, old_xid))?;
                let val = self.omap_val(new);
                self.tree_put(TreeId::NxOmap, &Self::omap_key(oid, txn), &val)?;
                self.vols[v].sb_paddr = new;
                self.vols[v].sb_xid = txn;
            }
            let touched = std::mem::replace(&mut self.vols[v].touched, true);
            let vol = &mut self.vols[v];
            let sb = &mut vol.sb;
            sb[256..264].copy_from_slice(&now.to_le_bytes()); // apfs_last_mod_time
            // apfs_modified_by: newest first, 8 entries of (id[32], timestamp, last_xid).
            let ours = sb[320..352].starts_with(MODIFIED_BY.as_bytes()) && sb[320 + MODIFIED_BY.len()] == 0;
            if !touched && !ours {
                sb.copy_within(320..320 + 48 * 7, 320 + 48);
                sb[320..352].fill(0);
                sb[320..320 + MODIFIED_BY.len()].copy_from_slice(MODIFIED_BY.as_bytes());
            }
            sb[352..360].copy_from_slice(&now.to_le_bytes());
            sb[360..368].copy_from_slice(&txn.to_le_bytes());
            sb[8..16].copy_from_slice(&vol.oid.to_le_bytes());
            sb[16..24].copy_from_slice(&txn.to_le_bytes());
            seal(sb);
            let (addr, data) = (vol.sb_paddr, sb.clone());
            vol.dirty = false;
            self.c.put_block(addr, data);
        }

        // Space manager structures in the internal pool, then the ephemeral objects. A free queue that
        // outgrew its node limit gives back the previous transaction's frees early.
        if self.sm.main_queue_len() > self.sm.main_queue_limit() {
            self.sm.drain(&self.c, txn - 1, txn)?;
        }
        self.sm.flush(&self.c, txn)?;
        let mut objs: Vec<(u32, u32, u64, Vec<u8>)> = vec![];
        for q in [SFQ_IP, SFQ_MAIN] {
            let nx = &mut self.nx;
            let mut new_oid = || {
                let oid = u64le(nx, 88);
                nx[88..96].copy_from_slice(&(oid + 1).to_le_bytes());
                oid
            };
            let nodes = self.sm.free_queue_nodes(q, txn, &mut new_oid, self.fq_roots[q].as_deref())?;
            for (i, (oid, data)) in nodes.into_iter().enumerate() {
                let ty = tree::OBJ_EPHEMERAL | if i == 0 { 2 } else { 3 };
                if i == 0 {
                    self.fq_roots[q] = Some(data.clone());
                }
                objs.push((ty, 9, oid, data));
            }
        }
        let mut sm_raw = self.sm.raw.clone();
        sm_raw[16..24].copy_from_slice(&txn.to_le_bytes());
        seal(&mut sm_raw);
        objs.insert(0, (tree::OBJ_EPHEMERAL | OBJECT_TYPE_SPACEMAN, 0, self.sm_oid, sm_raw));
        for e in &mut self.eph {
            e.data[16..24].copy_from_slice(&txn.to_le_bytes());
            seal(&mut e.data);
            objs.push((e.ty, e.subtype, e.oid, e.data.clone()));
        }

        // Checkpoint data area: ephemeral objects back to back, right after the current checkpoint's.
        // An object may not wrap past the end of the ring (readers map it linearly), so if the first
        // (the possibly multi-block space manager) wouldn't fit there, the checkpoint starts at 0.
        let nx = &self.nx;
        let (desc_base, data_base) = (u64le(nx, 112), u64le(nx, 120));
        let (desc_blocks, data_blocks) = (u32le(nx, 104), u32le(nx, 108));
        let (data_next, data_index, data_len) = (u32le(nx, 132), u32le(nx, 144), u32le(nx, 148));
        let (desc_next, desc_len) = (u32le(nx, 128), u32le(nx, 140));
        let blocks_of = |d: &Vec<u8>| (d.len() / bs) as u32;
        let total: u32 = objs.iter().map(|o| blocks_of(&o.3)).sum();
        let first = objs.first().map_or(1, |o| blocks_of(&o.3));
        let start = if data_next + first > data_blocks { 0 } else { data_next };
        let live = |i: u32| (i + data_blocks - data_index) % data_blocks < data_len;
        if total > data_blocks || (0..total).any(|k| live((start + k) % data_blocks)) {
            return Err(bad("checkpoint data area too small"));
        }
        let mut maps = vec![];
        let mut pos = start;
        for (ty, subtype, oid, data) in objs {
            let n = blocks_of(&data);
            if pos + n > data_blocks {
                return Err(bad("multi-block ephemeral object would wrap the checkpoint ring"));
            }
            let paddr = data_base + pos as u64;
            for (i, block) in data.chunks(bs).enumerate() {
                self.c.put_block(paddr + i as u64, block.to_vec());
            }
            maps.push((ty, subtype, oid, paddr, data.len() as u32));
            pos = (pos + n) % data_blocks;
        }
        let new_data = (start, total, pos);

        // Checkpoint descriptor area: map block(s), then the superblock.
        let per_map = (bs - 40) / 40;
        let n_maps = maps.len().div_ceil(per_map) as u32;
        if n_maps + 1 + desc_len > desc_blocks {
            return Err(bad("checkpoint descriptor area too small"));
        }
        let mut dpos = desc_next;
        for (i, chunk) in maps.chunks(per_map).enumerate() {
            let paddr = desc_base + dpos as u64;
            let mut b = vec![0u8; bs];
            b[8..16].copy_from_slice(&paddr.to_le_bytes());
            b[16..24].copy_from_slice(&txn.to_le_bytes());
            b[24..28].copy_from_slice(&(OBJ_PHYSICAL | OBJECT_TYPE_CHECKPOINT_MAP).to_le_bytes());
            let last = i as u32 == n_maps - 1;
            b[32..36].copy_from_slice(&(last as u32).to_le_bytes());
            b[36..40].copy_from_slice(&(chunk.len() as u32).to_le_bytes());
            for (j, &(ty, subtype, oid, addr, size)) in chunk.iter().enumerate() {
                let o = 40 + 40 * j;
                b[o..o + 4].copy_from_slice(&ty.to_le_bytes());
                b[o + 4..o + 8].copy_from_slice(&subtype.to_le_bytes());
                b[o + 8..o + 12].copy_from_slice(&size.to_le_bytes());
                b[o + 24..o + 32].copy_from_slice(&oid.to_le_bytes());
                b[o + 32..o + 40].copy_from_slice(&addr.to_le_bytes());
            }
            seal(&mut b);
            self.c.put_block(paddr, b);
            dpos = (dpos + 1) % desc_blocks;
        }
        let sb_paddr = desc_base + dpos as u64;
        let desc_index = desc_next;
        dpos = (dpos + 1) % desc_blocks;

        let nx = &mut self.nx;
        nx[16..24].copy_from_slice(&txn.to_le_bytes());
        nx[96..104].copy_from_slice(&(txn + 1).to_le_bytes());
        nx[128..132].copy_from_slice(&dpos.to_le_bytes());
        nx[132..136].copy_from_slice(&new_data.2.to_le_bytes());
        nx[136..140].copy_from_slice(&desc_index.to_le_bytes());
        nx[140..144].copy_from_slice(&(n_maps + 1).to_le_bytes());
        nx[144..148].copy_from_slice(&new_data.0.to_le_bytes());
        nx[148..152].copy_from_slice(&new_data.1.to_le_bytes());
        seal(nx);
        let nx = nx.clone();

        // Everything the superblock references must be durable before the superblock itself.
        let mut blocks: Vec<(u64, Vec<u8>)> = self.c.overlay.lock().unwrap().drain().collect();
        blocks.sort_by_key(|b| b.0);
        for (paddr, data) in &blocks {
            self.c.dev.write_at(paddr * bs as u64, data)?;
        }
        self.c.dev.flush()?;
        self.c.dev.write_at(sb_paddr * bs as u64, &nx)?;
        self.c.dev.flush()?;
        self.c.dev.write_at(0, &nx)?;
        self.c.dev.flush()?;

        self.c.xid = txn;
        self.c.superblock = nx;
        self.c.omap_tree = self.nx_omap.tree;
        self.txn = txn + 1;
        self.dirty = false;
        self.sm.drain(&self.c, self.txn.saturating_sub(2), self.txn)?;
        Ok(())
    }
}

impl Container {
    pub(crate) fn put_block(&self, paddr: u64, data: Vec<u8>) {
        self.overlay.lock().unwrap().insert(paddr, data);
    }
}
