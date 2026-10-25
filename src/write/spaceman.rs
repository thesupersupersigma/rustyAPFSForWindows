//! Block allocation (spec: "Space Manager"; the spec leaves most of it undocumented, so the rules here
//! follow what Apple-written images contain and what apfsck checks).
//!
//! - Main-device blocks are tracked by one bitmap block per chunk. Chunk bitmaps and chunk-info blocks
//!   live in the internal pool (IP) and are copied on write once per transaction.
//! - Freed blocks go to a free queue tagged with the freeing transaction and only return to the bitmaps
//!   two transactions later, so the previous checkpoint stays intact.
//! - The IP's own bitmap rotates through a ring of 16 copies.

use super::tree::{self, Def, Node, OBJ_EPHEMERAL};
use crate::container::{Container, OBJ_PHYSICAL, checksum_ok};
use crate::{bad, u16le, u32le, u64le};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io;

const OBJECT_TYPE_SPACEMAN_CIB: u32 = 0x7;
const OBJECT_TYPE_SPACEMAN_CAB: u32 = 0x6;
const CI_COUNT_MASK: u32 = 0x000f_ffff;
const IP_BM_INDEX_INVALID: u16 = 0xffff;
pub(crate) const SFQ_IP: usize = 0;
pub(crate) const SFQ_MAIN: usize = 1;

struct Chunk {
    xid: u64,
    addr: u64,
    block_count: u32, // raw field, count in the low 20 bits
    free_count: u32,  // raw field, count in the low 20 bits
    bitmap: u64,      // IP block holding the bitmap, 0 = chunk entirely free
}

struct Cib {
    addr: u64,
    xid: u64,
    chunks: Vec<Chunk>,
    dirty: bool,
}

struct Cab {
    addr: u64,
    xid: u64,
    cibs: Vec<u64>,
    dirty: bool,
}

pub(crate) struct Spaceman {
    /// The spaceman_phys object (ephemeral, rewritten every checkpoint).
    pub raw: Vec<u8>,
    bs: u64,
    bpc: u64,
    cpc: u64,
    cibs_per_cab: u64,
    cibs: Vec<Cib>,
    cabs: Vec<Cab>,
    bitmaps: HashMap<u64, Vec<u8>>,
    dirty_bitmaps: BTreeSet<u64>,
    ip_bitmap: Vec<u8>,
    ip_dirty: bool,
    /// Free queues: (xid, paddr) -> block count.
    pub fq: [BTreeMap<(u64, u64), u64>; 2],
    cursor: u64,
}

impl Spaceman {
    /// `eph` maps ephemeral oids to their current blocks (from the checkpoint map).
    pub(crate) fn load(c: &Container, raw: Vec<u8>, eph: &HashMap<u64, Vec<u8>>) -> io::Result<Spaceman> {
        let bs = c.block_size;
        if u32le(&raw, 32) as u64 != bs {
            return Err(bad("spaceman block size mismatch"));
        }
        if u64le(&raw, 96 + 8) != 0 {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "Fusion (tier 2) containers are read-only"));
        }
        let (bpc, cpc, cibs_per_cab) = (u32le(&raw, 36) as u64, u32le(&raw, 40) as u64, u32le(&raw, 44) as u64);
        let (cib_count, cab_count, addr_off) =
            (u32le(&raw, 64) as usize, u32le(&raw, 68) as usize, u32le(&raw, 80) as usize);
        let addrs = |n: usize| (0..n).map(|i| u64le(&raw, addr_off + 8 * i)).collect::<Vec<_>>();

        let mut cabs = vec![];
        let cib_addrs = if cab_count == 0 {
            addrs(cib_count)
        } else {
            let mut all = vec![];
            for a in addrs(cab_count) {
                let b = read_checked(c, a)?;
                let n = u32le(&b, 36) as usize;
                let cibs: Vec<u64> = (0..n).map(|i| u64le(&b, 40 + 8 * i)).collect();
                all.extend(&cibs);
                cabs.push(Cab { addr: a, xid: u64le(&b, 16), cibs, dirty: false });
            }
            all
        };
        let mut cibs = vec![];
        for a in cib_addrs {
            let b = read_checked(c, a)?;
            let n = u32le(&b, 36) as usize;
            let chunks = (0..n)
                .map(|i| {
                    let o = 40 + 32 * i;
                    Chunk {
                        xid: u64le(&b, o),
                        addr: u64le(&b, o + 8),
                        block_count: u32le(&b, o + 16),
                        free_count: u32le(&b, o + 20),
                        bitmap: u64le(&b, o + 24),
                    }
                })
                .collect();
            cibs.push(Cib { addr: a, xid: u64le(&b, 16), chunks, dirty: false });
        }

        // The current IP bitmap: one ring block per bitmap block.
        let (ip_bm_size, ip_bm_base, bm_off) = (u32le(&raw, 160) as usize, u64le(&raw, 168), u32le(&raw, 328) as usize);
        let mut ip_bitmap = Vec::with_capacity(ip_bm_size * bs as usize);
        for i in 0..ip_bm_size {
            ip_bitmap.extend(c.read_block(ip_bm_base + u16le(&raw, bm_off + 2 * i) as u64)?);
        }

        let mut fq = [BTreeMap::new(), BTreeMap::new()];
        for (q, map) in fq.iter_mut().enumerate() {
            let oid = u64le(&raw, 200 + 40 * q + 8);
            if oid != 0 {
                read_free_queue(eph, oid, map, 0)?;
            }
        }
        Ok(Spaceman {
            raw,
            bs,
            bpc,
            cpc,
            cibs_per_cab,
            cibs,
            cabs,
            bitmaps: HashMap::new(),
            dirty_bitmaps: BTreeSet::new(),
            ip_bitmap,
            ip_dirty: false,
            fq,
            cursor: 0,
        })
    }

    fn chunk(&mut self, idx: u64) -> &mut Chunk {
        let (cpc, i) = (self.cpc, idx);
        &mut self.cibs[(i / cpc) as usize].chunks[(i % cpc) as usize]
    }

    fn chunk_count(&self) -> u64 {
        u64le(&self.raw, 56)
    }

    fn bitmap(&mut self, c: &Container, idx: u64) -> io::Result<&mut Vec<u8>> {
        if !self.bitmaps.contains_key(&idx) {
            let addr = self.chunk(idx).bitmap;
            let b = if addr == 0 { vec![0; self.bs as usize] } else { c.read_block(addr)? };
            self.bitmaps.insert(idx, b);
        }
        Ok(self.bitmaps.get_mut(&idx).unwrap())
    }

    pub(crate) fn free_blocks(&self) -> u64 {
        u64le(&self.raw, 72)
    }

    fn add_free(&mut self, delta: i64) {
        let v = (u64le(&self.raw, 72) as i64 + delta) as u64;
        self.raw[72..80].copy_from_slice(&v.to_le_bytes());
    }

    /// Allocates up to `want` contiguous blocks (at least 1). Returns (start, count).
    pub(crate) fn alloc(&mut self, c: &Container, want: u64, xid: u64) -> io::Result<(u64, u64)> {
        let total_chunks = self.chunk_count();
        let start_chunk = self.cursor / self.bpc;
        for step in 0..=total_chunks {
            let idx = (start_chunk + step) % total_chunks;
            if self.chunk(idx).free_count & CI_COUNT_MASK == 0 {
                continue;
            }
            let (base, blocks) = {
                let ch = self.chunk(idx);
                (ch.addr, (ch.block_count & CI_COUNT_MASK) as u64)
            };
            let from = if step == 0 { self.cursor.saturating_sub(base).min(blocks) } else { 0 };
            let bm = self.bitmap(c, idx)?;
            let bit = |bm: &[u8], i: u64| bm[(i / 8) as usize] & (1 << (i % 8)) != 0;
            let Some(first) = (from..blocks).find(|&i| !bit(bm, i)).or_else(|| (0..from).find(|&i| !bit(bm, i))) else {
                continue;
            };
            let mut n = 1;
            while n < want && first + n < blocks && !bit(bm, first + n) {
                n += 1;
            }
            for i in first..first + n {
                bm[(i / 8) as usize] |= 1 << (i % 8);
            }
            self.dirty_bitmaps.insert(idx);
            let ch = self.chunk(idx);
            ch.free_count -= n as u32;
            ch.xid = xid;
            self.add_free(-(n as i64));
            self.cursor = base + first + n;
            return Ok((base + first, n));
        }
        Err(io::Error::new(io::ErrorKind::StorageFull, "APFS container is full"))
    }

    /// Queues blocks for freeing; they stay allocated until drained two transactions later.
    pub(crate) fn free(&mut self, paddr: u64, n: u64, xid: u64) {
        queue_insert(&mut self.fq[SFQ_MAIN], xid, paddr, n);
    }

    /// Returns queued blocks freed at or before `upto` to the bitmaps.
    pub(crate) fn drain(&mut self, c: &Container, upto: u64, xid: u64) -> io::Result<()> {
        let main: Vec<_> = self.fq[SFQ_MAIN].range(..(upto + 1, 0)).map(|(&k, &v)| (k, v)).collect();
        for ((qx, paddr), n) in main {
            self.fq[SFQ_MAIN].remove(&(qx, paddr));
            for b in paddr..paddr + n {
                let idx = b / self.bpc;
                let off = b - self.chunk(idx).addr;
                let bm = self.bitmap(c, idx)?;
                bm[(off / 8) as usize] &= !(1 << (off % 8));
                self.dirty_bitmaps.insert(idx);
                let ch = self.chunk(idx);
                ch.free_count += 1;
                ch.xid = xid;
            }
            self.add_free(n as i64);
        }
        let ip: Vec<_> = self.fq[SFQ_IP].range(..(upto + 1, 0)).map(|(&k, &v)| (k, v)).collect();
        let ip_base = u64le(&self.raw, 176);
        for ((qx, paddr), n) in ip {
            self.fq[SFQ_IP].remove(&(qx, paddr));
            for b in paddr - ip_base..paddr - ip_base + n {
                self.ip_bitmap[(b / 8) as usize] &= !(1 << (b % 8));
            }
            self.ip_dirty = true;
        }
        Ok(())
    }

    fn ip_alloc(&mut self) -> io::Result<u64> {
        let count = u64le(&self.raw, 152);
        let i = (0..count)
            .find(|&i| self.ip_bitmap[(i / 8) as usize] & (1 << (i % 8)) == 0)
            .ok_or_else(|| bad("internal pool is full (too many changes in one transaction)"))?;
        self.ip_bitmap[(i / 8) as usize] |= 1 << (i % 8);
        self.ip_dirty = true;
        Ok(u64le(&self.raw, 176) + i)
    }

    /// Writes changed chunk bitmaps, chunk-info blocks and the IP bitmap for transaction `xid`.
    pub(crate) fn flush(&mut self, c: &Container, xid: u64) -> io::Result<()> {
        let bs = self.bs as usize;
        for idx in std::mem::take(&mut self.dirty_bitmaps) {
            let new = self.ip_alloc()?;
            let old = self.chunk(idx).bitmap;
            if old != 0 {
                queue_insert(&mut self.fq[SFQ_IP], xid, old, 1);
            }
            c.put_block(new, self.bitmaps[&idx].clone());
            self.chunk(idx).bitmap = new;
            self.cibs[(idx / self.cpc) as usize].dirty = true;
        }
        let addr_off = u32le(&self.raw, 80) as usize;
        for i in 0..self.cibs.len() {
            if !self.cibs[i].dirty {
                continue;
            }
            let new = self.ip_alloc()?;
            queue_insert(&mut self.fq[SFQ_IP], xid, self.cibs[i].addr, 1);
            let cib = &mut self.cibs[i];
            cib.addr = new;
            cib.xid = cib.chunks.iter().map(|ch| ch.xid).max().unwrap_or(xid);
            cib.dirty = false;
            let mut b = vec![0u8; bs];
            header(&mut b, new, cib.xid, OBJ_PHYSICAL | OBJECT_TYPE_SPACEMAN_CIB);
            b[32..36].copy_from_slice(&(i as u32).to_le_bytes());
            b[36..40].copy_from_slice(&(cib.chunks.len() as u32).to_le_bytes());
            for (j, ch) in cib.chunks.iter().enumerate() {
                let o = 40 + 32 * j;
                b[o..o + 8].copy_from_slice(&ch.xid.to_le_bytes());
                b[o + 8..o + 16].copy_from_slice(&ch.addr.to_le_bytes());
                b[o + 16..o + 20].copy_from_slice(&ch.block_count.to_le_bytes());
                b[o + 20..o + 24].copy_from_slice(&ch.free_count.to_le_bytes());
                b[o + 24..o + 32].copy_from_slice(&ch.bitmap.to_le_bytes());
            }
            super::seal(&mut b);
            c.put_block(new, b);
            if self.cabs.is_empty() {
                self.raw[addr_off + 8 * i..addr_off + 8 * i + 8].copy_from_slice(&new.to_le_bytes());
            } else {
                let cab = &mut self.cabs[i / self.cibs_per_cab as usize];
                cab.cibs[i % self.cibs_per_cab as usize] = new;
                cab.dirty = true;
            }
        }
        for j in 0..self.cabs.len() {
            if !self.cabs[j].dirty {
                continue;
            }
            let new = self.ip_alloc()?;
            queue_insert(&mut self.fq[SFQ_IP], xid, self.cabs[j].addr, 1);
            let first = j * self.cibs_per_cab as usize;
            let cab_xid = (first..first + self.cabs[j].cibs.len()).map(|i| self.cibs[i].xid).max().unwrap_or(xid);
            let cab = &mut self.cabs[j];
            cab.addr = new;
            cab.xid = cab_xid;
            cab.dirty = false;
            let mut b = vec![0u8; bs];
            header(&mut b, new, cab.xid, OBJ_PHYSICAL | OBJECT_TYPE_SPACEMAN_CAB);
            b[32..36].copy_from_slice(&(j as u32).to_le_bytes());
            b[36..40].copy_from_slice(&(cab.cibs.len() as u32).to_le_bytes());
            for (i, a) in cab.cibs.iter().enumerate() {
                b[40 + 8 * i..48 + 8 * i].copy_from_slice(&a.to_le_bytes());
            }
            super::seal(&mut b);
            c.put_block(new, b);
            self.raw[addr_off + 8 * j..addr_off + 8 * j + 8].copy_from_slice(&new.to_le_bytes());
        }

        // Rotate each changed IP bitmap block to the next free ring slot.
        if self.ip_dirty {
            let (size, base) = (u32le(&self.raw, 160) as usize, u64le(&self.raw, 168));
            let (xid_off, bm_off, next_off) =
                (u32le(&self.raw, 324) as usize, u32le(&self.raw, 328) as usize, u32le(&self.raw, 332) as usize);
            let next = |raw: &[u8], i: u16| u16le(raw, next_off + 2 * i as usize);
            let set = |raw: &mut [u8], off: usize, v: u16| raw[off..off + 2].copy_from_slice(&v.to_le_bytes());
            for i in 0..size {
                let (head, tail) = (u16le(&self.raw, 320), u16le(&self.raw, 322));
                let new_head = next(&self.raw, head);
                set(&mut self.raw, next_off + 2 * head as usize, IP_BM_INDEX_INVALID);
                set(&mut self.raw, 320, new_head);
                let old = u16le(&self.raw, bm_off + 2 * i);
                set(&mut self.raw, bm_off + 2 * i, head);
                set(&mut self.raw, next_off + 2 * tail as usize, old);
                set(&mut self.raw, next_off + 2 * old as usize, IP_BM_INDEX_INVALID);
                set(&mut self.raw, 322, old);
                self.raw[xid_off + 8 * i..xid_off + 8 * i + 8].copy_from_slice(&xid.to_le_bytes());
                c.put_block(base + head as u64, self.ip_bitmap[i * bs..(i + 1) * bs].to_vec());
            }
            self.ip_dirty = false;
        }
        Ok(())
    }

    /// Serializes free queue `q` as ephemeral B-tree nodes. `new_oid` hands out oids for extra nodes.
    pub(crate) fn free_queue_nodes(
        &mut self,
        q: usize,
        xid: u64,
        new_oid: &mut dyn FnMut() -> u64,
        old_root: Option<&[u8]>,
    ) -> io::Result<Vec<(u64, Vec<u8>)>> {
        let fq_off = 200 + 40 * q;
        let root_oid = u64le(&self.raw, fq_off + 8);
        let entries: Vec<(Vec<u8>, Vec<u8>)> = self.fq[q]
            .iter()
            .map(|(&(x, p), &n)| {
                let mut k = x.to_le_bytes().to_vec();
                k.extend(p.to_le_bytes());
                (k, if n == 1 { vec![] } else { n.to_le_bytes().to_vec() })
            })
            .collect();
        let count: u64 = self.fq[q].values().sum();
        let oldest = self.fq[q].keys().next().map_or(0, |k| k.0);
        self.raw[fq_off..fq_off + 8].copy_from_slice(&count.to_le_bytes());
        self.raw[fq_off + 16..fq_off + 24].copy_from_slice(&oldest.to_le_bytes());
        let limit = u16le(&self.raw, fq_off + 24) as usize;

        let def =
            Def { subtype: 0x9, fixed: Some((16, 8)), virtual_vol: None, ephemeral: true, cmp: tree::freequeue_cmp };
        let bs = self.bs as usize;
        let mut info = match old_root {
            Some(r) => r[bs - tree::INFO..].to_vec(),
            None => {
                let mut i = vec![0u8; tree::INFO];
                i[0..4].copy_from_slice(&0xeu32.to_le_bytes()); // sequential insert, ghosts, ephemeral
                i[4..8].copy_from_slice(&(bs as u32).to_le_bytes());
                i[8..12].copy_from_slice(&16u32.to_le_bytes());
                i[12..16].copy_from_slice(&8u32.to_le_bytes());
                i
            }
        };
        // One leaf per ~140 records; a two-level tree is plenty for any queue under its node limit.
        let per_leaf = (bs - 56 - tree::INFO) / (16 + 8 + 4);
        let mut out = vec![];
        let mut root = Node { addr: 0, oid: root_oid, xid, level: 0, root: true, entries: vec![], info: vec![] };
        if entries.len() <= per_leaf {
            root.entries = entries;
        } else {
            root.level = 1;
            for chunk in entries.chunks(per_leaf) {
                let leaf =
                    Node { addr: 0, oid: new_oid(), xid, level: 0, root: false, entries: chunk.to_vec(), info: vec![] };
                root.entries.push((chunk[0].0.clone(), leaf.oid.to_le_bytes().to_vec()));
                out.push((leaf.oid, tree::serialize(&def, &leaf, bs)));
            }
        }
        if out.len() + 1 > limit {
            return Err(bad(format!("free queue needs {} nodes, limit is {limit}", out.len() + 1)));
        }
        if !self.fq[q].is_empty() {
            info[16..20].copy_from_slice(&16u32.to_le_bytes());
            info[20..24].copy_from_slice(&8u32.to_le_bytes());
        }
        info[24..32].copy_from_slice(&(self.fq[q].len() as u64).to_le_bytes());
        info[32..40].copy_from_slice(&(out.len() as u64 + 1).to_le_bytes());
        root.info = info;
        out.insert(0, (root_oid, tree::serialize(&def, &root, bs)));
        Ok(out)
    }

    /// Total queued entries in the main free queue (for deciding when to drain harder).
    pub(crate) fn main_queue_len(&self) -> usize {
        self.fq[SFQ_MAIN].len()
    }

    pub(crate) fn main_queue_limit(&self) -> usize {
        let limit = u16le(&self.raw, 200 + 40 * SFQ_MAIN + 24) as usize;
        let per_leaf = (self.bs as usize - 56 - tree::INFO) / (16 + 8 + 4);
        if limit <= 1 { per_leaf } else { (limit - 1) * per_leaf }
    }
}

fn queue_insert(q: &mut BTreeMap<(u64, u64), u64>, xid: u64, paddr: u64, n: u64) {
    let mut start = paddr;
    let mut len = n;
    // Merge with a range from the same transaction that ends right where this one starts.
    if let Some((&(px, pp), &pn)) = q.range(..(xid, paddr)).next_back()
        && px == xid
        && pp + pn == paddr
    {
        q.remove(&(px, pp));
        start = pp;
        len += pn;
    }
    if let Some(nn) = q.remove(&(xid, paddr + n)) {
        len += nn;
    }
    q.insert((xid, start), len);
}

fn header(b: &mut [u8], oid: u64, xid: u64, ty: u32) {
    b[8..16].copy_from_slice(&oid.to_le_bytes());
    b[16..24].copy_from_slice(&xid.to_le_bytes());
    b[24..28].copy_from_slice(&ty.to_le_bytes());
}

fn read_checked(c: &Container, addr: u64) -> io::Result<Vec<u8>> {
    let b = c.read_block(addr)?;
    if !checksum_ok(&b) {
        return Err(bad(format!("bad checksum on spaceman block {addr}")));
    }
    Ok(b)
}

fn read_free_queue(
    eph: &HashMap<u64, Vec<u8>>,
    oid: u64,
    out: &mut BTreeMap<(u64, u64), u64>,
    depth: u32,
) -> io::Result<()> {
    if depth > 8 {
        return Err(bad("free queue tree too deep"));
    }
    let data = eph.get(&oid).ok_or_else(|| bad(format!("free queue node {oid} missing from checkpoint")))?;
    let def = Def { subtype: 0x9, fixed: Some((16, 8)), virtual_vol: None, ephemeral: true, cmp: tree::freequeue_cmp };
    let node = tree::parse(&def, data)?;
    for (k, v) in &node.entries {
        if node.leaf() {
            out.insert((u64le(k, 0), u64le(k, 8)), if v.is_empty() { 1 } else { u64le(v, 0) });
        } else {
            read_free_queue(eph, u64le(v, 0), out, depth + 1)?;
        }
    }
    let _ = OBJ_EPHEMERAL;
    Ok(())
}
