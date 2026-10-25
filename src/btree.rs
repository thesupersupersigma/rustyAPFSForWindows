//! Generic APFS B-tree traversal (spec: "B-Trees").

use crate::container::{Container, OBJECT_TYPE_BTREE, OBJECT_TYPE_BTREE_NODE};
use crate::crypto::Xts;
use crate::{bad, slice, u16le, u32le, u64le};
use std::cmp::Ordering;
use std::io;

const BTNODE_ROOT: u16 = 0x1;
const BTNODE_LEAF: u16 = 0x2;
const BTNODE_FIXED_KV_SIZE: u16 = 0x4;
const NODE_HEADER: usize = 56; // obj_phys_t + btn_* fields
const INFO_SIZE: usize = 40; // btree_info_t at the end of a root node

/// Child-pointer resolver: virtual trees map oids through an object map, physical trees use them as-is.
pub(crate) type Resolve<'a> = &'a dyn Fn(u64) -> io::Result<u64>;
/// Record visitor: gets (key, value), returns `Ok(false)` to stop.
pub(crate) type Visit<'a> = &'a mut dyn FnMut(&[u8], &[u8]) -> io::Result<bool>;

/// Visits, in key order, every leaf record whose key `cmp` reports as `Equal`.
/// `cmp` must order keys against the wanted range: `Less` = before it, `Greater` = after it.
/// `visit` returns `Ok(false)` to stop early.
pub(crate) fn walk(
    c: &Container,
    root: u64,
    resolve: Resolve,
    cmp: &dyn Fn(&[u8]) -> Ordering,
    visit: Visit,
) -> io::Result<()> {
    walk_key(c, root, resolve, cmp, visit, None)
}

/// `walk` for trees whose nodes may be encrypted with `key` (an unlocked volume's trees).
pub(crate) fn walk_key(
    c: &Container,
    root: u64,
    resolve: Resolve,
    cmp: &dyn Fn(&[u8]) -> Ordering,
    visit: Visit,
    key: Option<&Xts>,
) -> io::Result<()> {
    let data = c.read_obj_key(root, OBJECT_TYPE_BTREE, key)?;
    let fixed = if u16le(&data, 32) & BTNODE_FIXED_KV_SIZE != 0 {
        let info = data.len() - INFO_SIZE;
        Some((u32le(&data, info + 8) as usize, u32le(&data, info + 12) as usize))
    } else {
        None
    };
    walk_node(c, &data, fixed, resolve, cmp, visit, key, 0)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)] // recursion state; bundling it into a struct would only move the noise
fn walk_node(
    c: &Container,
    data: &[u8],
    fixed: Option<(usize, usize)>,
    resolve: Resolve,
    cmp: &dyn Fn(&[u8]) -> Ordering,
    visit: Visit,
    key: Option<&Xts>,
    depth: u32,
) -> io::Result<bool> {
    if depth > 16 {
        return Err(bad("B-tree deeper than 16 levels (corrupt or looping)"));
    }
    let flags = u16le(data, 32);
    let leaf = flags & BTNODE_LEAF != 0;
    let nkeys = u32le(data, 36) as usize;
    let toc = NODE_HEADER + u16le(data, 40) as usize;
    let key_start = toc + u16le(data, 42) as usize;
    let val_end = data.len() - if flags & BTNODE_ROOT != 0 { INFO_SIZE } else { 0 };

    let entry = |i: usize| -> io::Result<(&[u8], &[u8])> {
        let (koff, klen, voff, vlen) = match fixed {
            Some((ks, vs)) => {
                let e = slice(data, toc + 4 * i, 4)?;
                (u16le(e, 0) as usize, ks, u16le(e, 2) as usize, if leaf { vs } else { 8 })
            }
            None => {
                let e = slice(data, toc + 8 * i, 8)?;
                (u16le(e, 0) as usize, u16le(e, 2) as usize, u16le(e, 4) as usize, u16le(e, 6) as usize)
            }
        };
        let vstart = val_end.checked_sub(voff).ok_or_else(|| bad("B-tree value offset out of node"))?;
        Ok((slice(data, key_start + koff, klen)?, slice(data, vstart, vlen)?))
    };

    if leaf {
        for i in 0..nkeys {
            let (k, v) = entry(i)?;
            match cmp(k) {
                Ordering::Less => {}
                Ordering::Equal => {
                    if !visit(k, v)? {
                        return Ok(false);
                    }
                }
                Ordering::Greater => return Ok(false),
            }
        }
        return Ok(true);
    }

    // Each index key is the smallest key of its child, so start at the last child that begins before the range.
    let mut start = 0;
    for i in 0..nkeys {
        if cmp(entry(i)?.0) == Ordering::Less {
            start = i;
        } else {
            break;
        }
    }
    for i in start..nkeys {
        let (k, v) = entry(i)?;
        if i > start && cmp(k) == Ordering::Greater {
            return Ok(false);
        }
        let child = c.read_obj_key(resolve(u64le(slice(v, 0, 8)?, 0))?, OBJECT_TYPE_BTREE_NODE, key)?;
        if !walk_node(c, &child, fixed, resolve, cmp, visit, key, depth + 1)? {
            return Ok(false);
        }
    }
    Ok(true)
}
