use crate::crypto::Xts;
use crate::device::Device;
use crate::{Volume, bad, btree, u32le, u64le};
use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::Mutex;

pub(crate) const OBJ_PHYSICAL: u32 = 0x4000_0000;
pub(crate) const OBJECT_TYPE_NX_SUPERBLOCK: u32 = 0x1;
pub(crate) const OBJECT_TYPE_BTREE: u32 = 0x2;
pub(crate) const OBJECT_TYPE_BTREE_NODE: u32 = 0x3;
pub(crate) const OBJECT_TYPE_OMAP: u32 = 0xb;
pub(crate) const OBJECT_TYPE_FS: u32 = 0xd;
const NX_MAGIC: &[u8; 4] = b"NXSB";

/// An APFS container: the whole partition or image, holding one or more volumes.
pub struct Container {
    pub(crate) dev: Device,
    pub block_size: u64,
    /// Transaction id of the checkpoint we mounted.
    pub xid: u64,
    /// The checkpoint's container superblock.
    pub superblock: Vec<u8>,
    /// Newer checkpoints we rejected, newest first, with the reason.
    pub skipped: Vec<String>,
    pub(crate) omap_tree: u64,
    /// Metadata blocks written by the open transaction but not yet on disk; reads see these first.
    pub(crate) overlay: Mutex<HashMap<u64, Vec<u8>>>,
}

impl Container {
    /// Opens an image, a bare APFS partition, or the first APFS partition of a GPT disk
    /// (e.g. `\\.\PhysicalDrive1`, which needs admin rights).
    pub fn open(path: impl AsRef<Path>) -> io::Result<Container> {
        Self::open_dev(Device::open(path.as_ref(), false, None)?)
    }

    /// Opens the `n`-th APFS partition (0-based, see `apfs_partitions`) of a GPT disk.
    pub fn open_partition(path: impl AsRef<Path>, n: usize) -> io::Result<Container> {
        Self::open_dev(Device::open(path.as_ref(), false, Some(n))?)
    }

    pub(crate) fn open_rw(path: &Path, partition: Option<usize>) -> io::Result<Container> {
        Self::open_dev(Device::open(path, true, partition)?)
    }

    /// Re-reads the container from disk through the same device handle (dropping the overlay).
    pub(crate) fn reopen(&self) -> io::Result<Container> {
        Self::open_dev(self.dev.try_clone()?)
    }

    fn open_dev(dev: Device) -> io::Result<Container> {
        let mut c = Container {
            dev,
            block_size: 4096,
            xid: 0,
            superblock: vec![],
            skipped: vec![],
            omap_tree: 0,
            overlay: Mutex::new(HashMap::new()),
        };

        let b0 = c.read_block(0)?;
        if &b0[32..36] != NX_MAGIC {
            return Err(bad("not an APFS container (no NXSB magic in block 0)"));
        }
        c.block_size = u32le(&b0, 36) as u64;
        if !c.block_size.is_power_of_two() || !(4096..=65536).contains(&c.block_size) {
            return Err(bad(format!("unsupported block size {}", c.block_size)));
        }
        let b0 = c.read_block(0)?;

        // The newest valid superblock in the checkpoint descriptor area wins (spec: "Mounting a Container").
        let desc_blocks = u32le(&b0, 104);
        let desc_base = u64le(&b0, 112);
        let mut candidates = vec![];
        if desc_blocks & 0x8000_0000 != 0 {
            // shortcut: descriptor area stored as a B-tree isn't handled, fall back to block 0's copy.
            candidates.push(b0);
        } else {
            for i in 0..desc_blocks as u64 {
                let b = c.read_block(desc_base + i)?;
                if &b[32..36] == NX_MAGIC && u32le(&b, 24) & 0xffff == OBJECT_TYPE_NX_SUPERBLOCK {
                    candidates.push(b);
                }
            }
        }
        candidates.sort_by_key(|b| std::cmp::Reverse(u64le(b, 16)));

        for sb in candidates {
            let xid = u64le(&sb, 16);
            if !checksum_ok(&sb) {
                c.skipped.push(format!("Skipping superblock xid={xid}: Invalid nx_superblock checksum"));
                continue;
            }
            match c.omap_tree_of(u64le(&sb, 160)) {
                Ok(tree) => {
                    c.xid = xid;
                    c.omap_tree = tree;
                    c.superblock = sb;
                    return Ok(c);
                }
                Err(e) => c.skipped.push(format!("Skipping superblock xid={xid}: invalid OMAP ({e})")),
            }
        }
        Err(bad(format!("no valid checkpoint found: {:?}", c.skipped)))
    }

    pub fn read_block(&self, paddr: u64) -> io::Result<Vec<u8>> {
        if let Some(b) = self.overlay.lock().unwrap().get(&paddr) {
            return Ok(b.clone());
        }
        let mut buf = vec![0; self.block_size as usize];
        self.read_at(paddr * self.block_size, &mut buf)?;
        Ok(buf)
    }

    pub(crate) fn read_at(&self, off: u64, buf: &mut [u8]) -> io::Result<()> {
        self.dev.read_at(off, buf)
    }

    /// Reads a physical object and checks its checksum and type.
    pub(crate) fn read_obj(&self, paddr: u64, want_type: u32) -> io::Result<Vec<u8>> {
        self.read_obj_key(paddr, want_type, None)
    }

    /// Like `read_obj`, but a block that fails its checksum is decrypted with `key` and checked again.
    /// Encrypted volumes encrypt their own trees, not the container's, so trying plaintext first is safe.
    pub(crate) fn read_obj_key(&self, paddr: u64, want_type: u32, key: Option<&Xts>) -> io::Result<Vec<u8>> {
        let mut b = self.read_block(paddr)?;
        if !checksum_ok(&b) {
            match key {
                Some(k) => k.decrypt(&mut b, paddr * self.block_size / 512),
                None => return Err(bad(format!("bad checksum on object at block {paddr}"))),
            }
            if !checksum_ok(&b) {
                return Err(bad(format!("bad checksum on object at block {paddr} (also after decrypting)")));
            }
        }
        let ty = u32le(&b, 24) & 0xffff;
        if ty != want_type {
            return Err(bad(format!("object at block {paddr} has type {ty:#x}, expected {want_type:#x}")));
        }
        Ok(b)
    }

    /// Returns the physical address of an object map's B-tree root.
    pub(crate) fn omap_tree_of(&self, omap_paddr: u64) -> io::Result<u64> {
        let omap = self.read_obj(omap_paddr, OBJECT_TYPE_OMAP)?;
        let tree = u64le(&omap, 48);
        self.read_obj(tree, OBJECT_TYPE_BTREE)?;
        Ok(tree)
    }

    /// Resolves a virtual object id to a physical block: the newest mapping with xid <= `xid`.
    pub(crate) fn omap_lookup(&self, omap_tree: u64, oid: u64, xid: u64) -> io::Result<u64> {
        let mut found = None;
        btree::walk(
            self,
            omap_tree,
            &|child| Ok(child), // omap trees are physical
            &|k| u64le(k, 0).cmp(&oid),
            &mut |k, v| {
                if u64le(k, 8) <= xid {
                    found = Some(u64le(v, 8));
                }
                Ok(true)
            },
        )?;
        found
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("oid {oid} not in object map at xid {xid}")))
    }

    pub fn volumes(&self) -> io::Result<Vec<Volume<'_>>> {
        let max = u32le(&self.superblock, 180).min(100) as usize;
        let mut out = vec![];
        for i in 0..max {
            let oid = u64le(&self.superblock, 184 + 8 * i);
            if oid != 0 {
                let paddr = self.omap_lookup(self.omap_tree, oid, self.xid)?;
                out.push(Volume::new(self, self.read_obj(paddr, OBJECT_TYPE_FS)?, self.xid)?);
            }
        }
        Ok(out)
    }
}

pub(crate) fn checksum_ok(block: &[u8]) -> bool {
    fletcher64(&block[8..]) == u64le(block, 0)
}

/// Fletcher-64 as defined in the spec ("Checksum"). The sums are reduced every 4096 words rather than
/// every word: same result, and no overflow for objects of any size.
pub(crate) fn fletcher64(data: &[u8]) -> u64 {
    const M: u64 = 0xffff_ffff;
    let (mut s1, mut s2) = (0u64, 0u64);
    for chunk in data.chunks(4 * 4096) {
        for w in chunk.chunks_exact(4) {
            s1 += u32::from_le_bytes(w.try_into().unwrap()) as u64;
            s2 += s1;
        }
        (s1, s2) = (s1 % M, s2 % M);
    }
    let c1 = M - ((s1 + s2) % M);
    let c2 = M - ((s1 + c1) % M);
    (c2 << 32) | c1
}
