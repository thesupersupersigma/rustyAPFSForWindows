//! Copy-on-write B-tree updates (spec: "B-Trees"). Nodes are rebuilt compactly on every change, so the
//! key and value free lists are always empty.

use super::Writer;
use crate::container::{OBJ_PHYSICAL, OBJECT_TYPE_BTREE, OBJECT_TYPE_BTREE_NODE};
use crate::{bad, slice, u16le, u32le, u64le};
use std::cmp::Ordering;
use std::io;

pub(crate) const OBJ_EPHEMERAL: u32 = 0x8000_0000;
const BTNODE_ROOT: u16 = 0x1;
const BTNODE_LEAF: u16 = 0x2;
const BTNODE_FIXED_KV_SIZE: u16 = 0x4;
const BTOFF_INVALID: u16 = 0xffff;
/// A node's records as (key, value) pairs.
type Records = Vec<(Vec<u8>, Vec<u8>)>;

const HEADER: usize = 56;
pub(crate) const INFO: usize = 40;

/// The trees the writer changes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum TreeId {
    /// The container's object map (maps volume superblocks).
    NxOmap,
    VolOmap(usize),
    /// A volume's file-system tree (virtual nodes, mapped through the volume omap).
    Fs(usize),
    ExtentRef(usize),
}

/// How a tree is laid out and stored.
pub(crate) struct Def {
    pub subtype: u32,
    pub fixed: Option<(usize, usize)>,
    /// `Some(volume)` for virtual trees whose node oids map through that volume's omap.
    pub virtual_vol: Option<usize>,
    pub ephemeral: bool,
    pub cmp: fn(&[u8], &[u8]) -> Ordering,
}

#[derive(Clone, Debug)]
pub(crate) struct Node {
    /// Physical block, 0 if never stored.
    pub addr: u64,
    pub oid: u64,
    pub xid: u64,
    pub level: u16,
    pub root: bool,
    /// (key, value); an empty value in a fixed-size tree is a ghost record.
    pub entries: Vec<(Vec<u8>, Vec<u8>)>,
    pub info: Vec<u8>,
}

impl Node {
    pub(crate) fn leaf(&self) -> bool {
        self.level == 0
    }
}

pub(crate) fn omap_cmp(a: &[u8], b: &[u8]) -> Ordering {
    (u64le(a, 0), u64le(a, 8)).cmp(&(u64le(b, 0), u64le(b, 8)))
}

/// File-system tree order: object id, record type, then the type's own sort key.
pub(crate) fn fs_cmp(a: &[u8], b: &[u8]) -> Ordering {
    const MASK: u64 = 0x0fff_ffff_ffff_ffff;
    let (ha, hb) = (u64le(a, 0), u64le(b, 0));
    (ha & MASK).cmp(&(hb & MASK)).then((ha >> 60).cmp(&(hb >> 60))).then_with(|| match ha >> 60 {
        // Hashed directory record: hash (without the length bits), then the raw name.
        9 => (u32le(a, 8) >> 10).cmp(&(u32le(b, 8) >> 10)).then_with(|| cstr(&a[12..]).cmp(cstr(&b[12..]))),
        // Extended attribute / snapshot name: the name.
        4 | 11 => cstr(&a[10..]).cmp(cstr(&b[10..])),
        // File extent (logical address) / sibling link (sibling id).
        8 | 5 => u64le(a, 8).cmp(&u64le(b, 8)),
        _ => Ordering::Equal,
    })
}

/// Extent-reference tree order: physical address, then record type.
pub(crate) fn extentref_cmp(a: &[u8], b: &[u8]) -> Ordering {
    const MASK: u64 = 0x0fff_ffff_ffff_ffff;
    let (ha, hb) = (u64le(a, 0), u64le(b, 0));
    (ha & MASK).cmp(&(hb & MASK)).then((ha >> 60).cmp(&(hb >> 60)))
}

pub(crate) fn freequeue_cmp(a: &[u8], b: &[u8]) -> Ordering {
    omap_cmp(a, b) // (xid, paddr)
}

fn cstr(b: &[u8]) -> &[u8] {
    &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]
}

/// Space a record takes in a node: its table-of-contents entry plus key and value bytes.
fn rec_size(def: &Def, leaf: bool, k: &[u8], v: &[u8]) -> usize {
    match def.fixed {
        Some((ks, vs)) => {
            4 + ks
                + if !leaf {
                    8
                } else if v.is_empty() {
                    0
                } else {
                    vs
                }
        }
        None => 8 + k.len() + v.len(),
    }
}

/// Table-of-contents size. Fixed-size trees preallocate it for a full node (as apfsck expects);
/// variable-size trees round up to 8 entries like Apple's implementation.
fn toc_len(def: &Def, leaf: bool, n: usize, bs: usize) -> usize {
    match def.fixed {
        Some((ks, vs)) => (bs - HEADER) / (ks + if leaf { vs } else { 8 } + 4) * 4,
        None => n.max(1).div_ceil(8) * 8 * 8,
    }
}

fn fits(def: &Def, node: &Node, bs: usize) -> bool {
    let data: usize = node
        .entries
        .iter()
        .map(|(k, v)| rec_size(def, node.leaf(), k, v) - if def.fixed.is_some() { 4 } else { 8 })
        .sum();
    let toc = toc_len(def, node.leaf(), node.entries.len(), bs);
    let cap_entries = if def.fixed.is_some() { toc / 4 } else { usize::MAX };
    node.entries.len() <= cap_entries && HEADER + toc + data + if node.root { INFO } else { 0 } <= bs
}

/// Splits a node's records into pieces that each fit in a non-root node, balanced by size.
fn split(def: &Def, leaf: bool, entries: Vec<(Vec<u8>, Vec<u8>)>, bs: usize) -> Vec<Vec<(Vec<u8>, Vec<u8>)>> {
    let toc = toc_len(def, leaf, entries.len(), bs);
    let tocsz = if def.fixed.is_some() { 4 } else { 8 };
    let total: usize = entries.iter().map(|(k, v)| rec_size(def, leaf, k, v)).sum();
    // Leave the variable-size table room to round up.
    let usable = bs - HEADER - if def.fixed.is_some() { toc } else { 8 * tocsz };
    let pieces = total.div_ceil(usable * 9 / 10).max(2);
    let target = total.div_ceil(pieces);
    let max_count = if def.fixed.is_some() { toc / 4 } else { usize::MAX };
    let mut out: Vec<Vec<(Vec<u8>, Vec<u8>)>> = vec![vec![]];
    let mut cur = 0;
    for e in entries {
        let sz = rec_size(def, leaf, &e.0, &e.1);
        let last = out.last().unwrap();
        if !last.is_empty() && (cur + sz > target.max(sz) || last.len() >= max_count) {
            out.push(vec![]);
            cur = 0;
        }
        cur += sz;
        out.last_mut().unwrap().push(e);
    }
    out
}

pub(crate) fn parse(def: &Def, data: &[u8]) -> io::Result<Node> {
    let flags = u16le(data, 32);
    let root = flags & BTNODE_ROOT != 0;
    let leaf = flags & BTNODE_LEAF != 0;
    let nkeys = u32le(data, 36) as usize;
    let toc = HEADER + u16le(data, 40) as usize;
    let key_start = toc + u16le(data, 42) as usize;
    let val_end = data.len() - if root { INFO } else { 0 };
    let mut entries = Vec::with_capacity(nkeys);
    for i in 0..nkeys {
        let (koff, klen, voff, vlen) = match def.fixed {
            Some((ks, vs)) => {
                let e = slice(data, toc + 4 * i, 4)?;
                let voff = u16le(e, 2);
                let vlen = if voff == BTOFF_INVALID {
                    0
                } else if leaf {
                    vs
                } else {
                    8
                };
                (u16le(e, 0) as usize, ks, if voff == BTOFF_INVALID { 0 } else { voff as usize }, vlen)
            }
            None => {
                let e = slice(data, toc + 8 * i, 8)?;
                (u16le(e, 0) as usize, u16le(e, 2) as usize, u16le(e, 4) as usize, u16le(e, 6) as usize)
            }
        };
        let k = slice(data, key_start + koff, klen)?.to_vec();
        let v = if vlen == 0 {
            vec![]
        } else {
            slice(data, val_end.checked_sub(voff).ok_or_else(|| bad("B-tree value offset out of node"))?, vlen)?
                .to_vec()
        };
        entries.push((k, v));
    }
    Ok(Node {
        addr: 0,
        oid: u64le(data, 8),
        xid: u64le(data, 16),
        level: u16le(data, 34),
        root,
        entries,
        info: if root { data[data.len() - INFO..].to_vec() } else { vec![] },
    })
}

pub(crate) fn serialize(def: &Def, node: &Node, bs: usize) -> Vec<u8> {
    let mut b = vec![0u8; bs];
    let leaf = node.leaf();
    let storage = if def.ephemeral {
        OBJ_EPHEMERAL
    } else if def.virtual_vol.is_some() {
        0
    } else {
        OBJ_PHYSICAL
    };
    let ty = storage | if node.root { OBJECT_TYPE_BTREE } else { OBJECT_TYPE_BTREE_NODE };
    b[8..16].copy_from_slice(&node.oid.to_le_bytes());
    b[16..24].copy_from_slice(&node.xid.to_le_bytes());
    b[24..28].copy_from_slice(&ty.to_le_bytes());
    b[28..32].copy_from_slice(&def.subtype.to_le_bytes());
    let flags = if node.root { BTNODE_ROOT } else { 0 }
        | if leaf { BTNODE_LEAF } else { 0 }
        | if def.fixed.is_some() { BTNODE_FIXED_KV_SIZE } else { 0 };
    b[32..34].copy_from_slice(&flags.to_le_bytes());
    b[34..36].copy_from_slice(&node.level.to_le_bytes());
    b[36..40].copy_from_slice(&(node.entries.len() as u32).to_le_bytes());
    let toc = toc_len(def, leaf, node.entries.len(), bs);
    put16(&mut b, 40, 0);
    put16(&mut b, 42, toc as u16);
    let key_start = HEADER + toc;
    let val_end = bs - if node.root { INFO } else { 0 };
    let (mut koff, mut voff) = (0usize, 0usize);
    for (i, (k, v)) in node.entries.iter().enumerate() {
        b[key_start + koff..key_start + koff + k.len()].copy_from_slice(k);
        let vstored = if v.is_empty() && def.fixed.is_some() {
            BTOFF_INVALID
        } else {
            voff += v.len();
            b[val_end - voff..val_end - voff + v.len()].copy_from_slice(v);
            voff as u16
        };
        match def.fixed {
            Some(_) => {
                put16(&mut b, HEADER + 4 * i, koff as u16);
                put16(&mut b, HEADER + 4 * i + 2, vstored);
            }
            None => {
                put16(&mut b, HEADER + 8 * i, koff as u16);
                put16(&mut b, HEADER + 8 * i + 2, k.len() as u16);
                put16(&mut b, HEADER + 8 * i + 4, vstored);
                put16(&mut b, HEADER + 8 * i + 6, v.len() as u16);
            }
        }
        koff += k.len();
    }
    put16(&mut b, 44, koff as u16);
    put16(&mut b, 46, (val_end - voff - key_start - koff) as u16);
    put16(&mut b, 48, BTOFF_INVALID);
    put16(&mut b, 52, BTOFF_INVALID);
    if node.root {
        b[bs - INFO..].copy_from_slice(&node.info);
    }
    super::seal(&mut b);
    b
}

fn put16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

impl Writer {
    pub(crate) fn def(&self, t: TreeId) -> Def {
        match t {
            TreeId::NxOmap | TreeId::VolOmap(_) => {
                Def { subtype: 0xb, fixed: Some((16, 16)), virtual_vol: None, ephemeral: false, cmp: omap_cmp }
            }
            TreeId::Fs(v) => Def { subtype: 0xe, fixed: None, virtual_vol: Some(v), ephemeral: false, cmp: fs_cmp },
            TreeId::ExtentRef(_) => {
                Def { subtype: 0xf, fixed: None, virtual_vol: None, ephemeral: false, cmp: extentref_cmp }
            }
        }
    }

    /// Root pointer: a physical address, or an oid for virtual trees.
    fn root_ptr(&self, t: TreeId) -> u64 {
        match t {
            TreeId::NxOmap => self.nx_omap.tree,
            TreeId::VolOmap(v) => self.vols[v].omap.tree,
            TreeId::Fs(v) => u64le(&self.vols[v].sb, 136),
            TreeId::ExtentRef(v) => u64le(&self.vols[v].sb, 144),
        }
    }

    fn set_root_ptr(&mut self, t: TreeId, ptr: u64) -> io::Result<()> {
        match t {
            TreeId::NxOmap => {
                self.nx_omap.tree = ptr;
                let addr = self.store_omap_phys(None)?;
                self.nx[160..168].copy_from_slice(&addr.to_le_bytes());
            }
            TreeId::VolOmap(v) => {
                self.vols[v].omap.tree = ptr;
                let addr = self.store_omap_phys(Some(v))?;
                self.vols[v].sb[128..136].copy_from_slice(&addr.to_le_bytes());
                self.vols[v].dirty = true;
            }
            TreeId::Fs(_) => {} // the root keeps its virtual oid
            TreeId::ExtentRef(v) => {
                self.vols[v].sb[144..152].copy_from_slice(&ptr.to_le_bytes());
                self.vols[v].dirty = true;
            }
        }
        Ok(())
    }

    fn resolve(&self, def: &Def, ptr: u64) -> io::Result<u64> {
        match def.virtual_vol {
            Some(v) => self.c.omap_lookup(self.vols[v].omap.tree, ptr, self.txn),
            None => Ok(ptr),
        }
    }

    pub(crate) fn load(&self, def: &Def, ptr: u64) -> io::Result<Node> {
        let addr = self.resolve(def, ptr)?;
        let data = self.c.read_block(addr)?;
        if !crate::container::checksum_ok(&data) {
            return Err(bad(format!("bad checksum on B-tree node at block {addr}")));
        }
        let mut n = parse(def, &data)?;
        n.addr = addr;
        Ok(n)
    }

    /// Writes a node copy-on-write and returns the pointer its parent should hold.
    fn store(&mut self, t: TreeId, def: &Def, node: &mut Node) -> io::Result<u64> {
        let owner = self.owner(t);
        if node.xid != self.txn || node.addr == 0 {
            let new = self.alloc_meta(owner)?;
            if node.addr != 0 {
                self.free_meta(owner, node.addr)?;
            }
            if let Some(v) = def.virtual_vol {
                if node.oid == 0 {
                    node.oid = self.next_oid();
                } else if node.addr != 0 {
                    self.omap_unmap(v, node.oid, node.xid)?;
                }
                self.omap_map(v, node.oid, new)?;
            } else {
                node.oid = new;
            }
            node.addr = new;
            node.xid = self.txn;
        }
        let bs = self.c.block_size as usize;
        self.c.put_block(node.addr, serialize(def, node, bs));
        Ok(node.oid)
    }

    /// Frees a node that left the tree.
    fn discard(&mut self, t: TreeId, def: &Def, node: &Node) -> io::Result<()> {
        if node.addr == 0 {
            return Ok(());
        }
        self.free_meta(self.owner(t), node.addr)?;
        if let Some(v) = def.virtual_vol {
            self.omap_unmap(v, node.oid, node.xid)?;
        }
        Ok(())
    }

    /// The volume a tree's blocks are charged to (None for the container's own trees).
    fn owner(&self, t: TreeId) -> Option<usize> {
        match t {
            TreeId::NxOmap => None,
            TreeId::VolOmap(v) | TreeId::Fs(v) | TreeId::ExtentRef(v) => Some(v),
        }
    }

    pub(crate) fn tree_get(&self, t: TreeId, key: &[u8]) -> io::Result<Option<Vec<u8>>> {
        let def = self.def(t);
        let mut node = self.load(&def, self.root_ptr(t))?;
        while !node.leaf() {
            let i = child_index(&def, &node, key);
            node = self.load(&def, u64le(&node.entries[i].1, 0))?;
        }
        Ok(node.entries.binary_search_by(|(k, _)| (def.cmp)(k, key)).ok().map(|i| node.entries[i].1.clone()))
    }

    /// Inserts or replaces a record; returns the old value.
    pub(crate) fn tree_put(&mut self, t: TreeId, key: &[u8], val: &[u8]) -> io::Result<Option<Vec<u8>>> {
        let mut old = None;
        self.modify(t, key, &mut |entries, pos| match pos {
            Ok(i) => {
                old = Some(std::mem::replace(&mut entries[i].1, val.to_vec()));
                0
            }
            Err(i) => {
                entries.insert(i, (key.to_vec(), val.to_vec()));
                1
            }
        })?;
        Ok(old)
    }

    /// Removes a record; returns its value if it existed.
    pub(crate) fn tree_del(&mut self, t: TreeId, key: &[u8]) -> io::Result<Option<Vec<u8>>> {
        let mut old = None;
        self.modify(t, key, &mut |entries, pos| match pos {
            Ok(i) => {
                old = Some(entries.remove(i).1);
                -1
            }
            Err(_) => 0,
        })?;
        Ok(old)
    }

    /// Descends to the leaf for `key`, lets `f` edit its records (returning the change in record count),
    /// then rewrites the path up to the root, splitting or dropping nodes as needed.
    fn modify(
        &mut self,
        t: TreeId,
        key: &[u8],
        f: &mut dyn FnMut(&mut Records, Result<usize, usize>) -> i64,
    ) -> io::Result<()> {
        let def = self.def(t);
        let bs = self.c.block_size as usize;
        let mut path: Vec<(Node, usize)> = vec![];
        let mut node = self.load(&def, self.root_ptr(t))?;
        while !node.leaf() {
            let i = child_index(&def, &node, key);
            let child = self.load(&def, u64le(&node.entries[i].1, 0))?;
            path.push((node, i));
            node = child;
        }
        let pos = node.entries.binary_search_by(|(k, _)| (def.cmp)(k, key));
        let key_delta = f(&mut node.entries, pos);
        if key_delta == 0 && pos.is_err() {
            return Ok(()); // nothing changed
        }
        let (mut longest_k, mut longest_v) = (0u32, 0u32);
        if let Ok(i) | Err(i) = pos
            && let Some((k, v)) = node.entries.get(i)
            && key_delta >= 0
        {
            (longest_k, longest_v) = (k.len() as u32, v.len() as u32);
        }

        let mut node_delta: i64 = 0;
        loop {
            if node.root {
                // Grow the tree while the root overflows.
                while !fits(&def, &node, bs) {
                    let pieces = split(&def, node.leaf(), std::mem::take(&mut node.entries), bs);
                    for piece in pieces {
                        let mut child = Node {
                            addr: 0,
                            oid: 0,
                            xid: 0,
                            level: node.level,
                            root: false,
                            entries: piece,
                            info: vec![],
                        };
                        let ptr = self.store(t, &def, &mut child)?;
                        node.entries.push((child.entries[0].0.clone(), ptr.to_le_bytes().to_vec()));
                        node_delta += 1;
                    }
                    node.level += 1;
                }
                // An index root whose children were all removed becomes an empty leaf again.
                if node.entries.is_empty() {
                    node.level = 0;
                }
                let info_len = node.info.len();
                let info = &mut node.info[info_len - INFO..];
                let kc = u64le(info, 24) as i64 + key_delta;
                let nc = u64le(info, 32) as i64 + node_delta;
                info[24..32].copy_from_slice(&(kc as u64).to_le_bytes());
                info[32..40].copy_from_slice(&(nc as u64).to_le_bytes());
                if longest_k > u32le(info, 16) {
                    info[16..20].copy_from_slice(&longest_k.to_le_bytes());
                }
                if longest_v > u32le(info, 20) {
                    info[20..24].copy_from_slice(&longest_v.to_le_bytes());
                }
                let ptr = self.store(t, &def, &mut node)?;
                return self.set_root_ptr(t, ptr);
            }

            let (mut parent, idx) = path.pop().expect("non-root node has a parent");
            if node.entries.is_empty() {
                self.discard(t, &def, &node)?;
                parent.entries.remove(idx);
                node_delta -= 1;
            } else if fits(&def, &node, bs) {
                let ptr = self.store(t, &def, &mut node)?;
                parent.entries[idx] = (node.entries[0].0.clone(), ptr.to_le_bytes().to_vec());
            } else {
                let mut pieces = split(&def, node.leaf(), std::mem::take(&mut node.entries), bs).into_iter();
                node.entries = pieces.next().unwrap();
                let ptr = self.store(t, &def, &mut node)?;
                let mut repl = vec![(node.entries[0].0.clone(), ptr.to_le_bytes().to_vec())];
                for piece in pieces {
                    let mut sib =
                        Node { addr: 0, oid: 0, xid: 0, level: node.level, root: false, entries: piece, info: vec![] };
                    let ptr = self.store(t, &def, &mut sib)?;
                    repl.push((sib.entries[0].0.clone(), ptr.to_le_bytes().to_vec()));
                    node_delta += 1;
                }
                parent.entries.splice(idx..idx + 1, repl);
            }
            node = parent;
        }
    }
}

/// Index of the child whose range holds `key`: the last child whose first key is <= `key`.
fn child_index(def: &Def, node: &Node, key: &[u8]) -> usize {
    node.entries.partition_point(|(k, _)| (def.cmp)(k, key) != Ordering::Greater).saturating_sub(1)
}
