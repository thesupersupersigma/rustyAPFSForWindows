//! Transparent file compression ("decmpfs"): the com.apple.decmpfs xattr header, with the data
//! either inline in that xattr or in the com.apple.ResourceFork xattr.
//! Apple's spec doesn't document this; the layout follows xnu's public decmpfs.h.

use crate::{bad, slice, u32le, u64le};
use std::io::{self, Read};

const DECMPFS_MAGIC: u32 = 0x636d_7066; // "fpmc"
const CHUNK: usize = 65536;

/// Returns true when this compression type keeps its data in the resource fork.
pub(crate) fn needs_resource_fork(decmpfs: &[u8]) -> bool {
    decmpfs.len() >= 16 && matches!(u32le(decmpfs, 4), 4 | 8 | 12)
}

pub(crate) fn decompress(decmpfs: &[u8], rsrc: Option<&[u8]>) -> io::Result<Vec<u8>> {
    if decmpfs.len() < 16 || u32le(decmpfs, 0) != DECMPFS_MAGIC {
        return Err(bad("bad com.apple.decmpfs header"));
    }
    let ty = u32le(decmpfs, 4);
    let size = usize::try_from(u64le(decmpfs, 8)).map_err(|_| bad("compressed size too large"))?;
    let inline = &decmpfs[16..];
    let fork = || rsrc.ok_or_else(|| bad(format!("compression type {ty} needs a resource fork")));

    let mut out = match ty {
        1 => inline.to_vec(),
        3 => zlib(inline, size)?,
        4 => zlib_fork(fork()?, size)?,
        7 => lzvn(inline, size)?,
        8 => chunked(fork()?, size, lzvn)?,
        11 => lzfse(inline, size)?,
        12 => chunked(fork()?, size, lzfse)?,
        _ => return Err(io::Error::new(io::ErrorKind::Unsupported, format!("decmpfs compression type {ty}"))),
    };
    if out.len() < size {
        return Err(bad(format!("decompressed {} bytes, expected {size}", out.len())));
    }
    out.truncate(size);
    Ok(out)
}

fn zlib(b: &[u8], max: usize) -> io::Result<Vec<u8>> {
    // A low nibble of 0xf can't start a zlib stream, so it marks stored (uncompressed) data.
    if b.first().is_some_and(|x| x & 0x0f == 0x0f) {
        return Ok(b[1..].to_vec());
    }
    let mut out = Vec::with_capacity(max.min(CHUNK));
    flate2::read::ZlibDecoder::new(b).take(max as u64).read_to_end(&mut out)?;
    Ok(out)
}

fn lzvn(b: &[u8], max: usize) -> io::Result<Vec<u8>> {
    if b.first() == Some(&0x06) {
        return Ok(b[1..].to_vec()); // 0x06 alone is LZVN's end-of-stream opcode, so it marks stored data
    }
    // lzfse_rust only decodes framed streams, so wrap the raw LZVN payload in a "bvxn" block.
    let mut framed = Vec::with_capacity(b.len() + 16);
    framed.extend_from_slice(b"bvxn");
    framed.extend_from_slice(&(max as u32).to_le_bytes());
    framed.extend_from_slice(&(b.len() as u32).to_le_bytes());
    framed.extend_from_slice(b);
    framed.extend_from_slice(b"bvx$");
    lzfse(&framed, max)
}

fn lzfse(b: &[u8], max: usize) -> io::Result<Vec<u8>> {
    if b.first() == Some(&0xff) {
        return Ok(b[1..].to_vec());
    }
    let mut out = Vec::with_capacity(max.min(CHUNK));
    lzfse_rust::decode_bytes(b, &mut out).map_err(|e| bad(format!("lzfse: {e}")))?;
    Ok(out)
}

/// zlib resource fork: a classic Mac resource fork whose single resource holds a chunk table.
fn zlib_fork(rsrc: &[u8], size: usize) -> io::Result<Vec<u8>> {
    let data_off = u32::from_be_bytes(slice(rsrc, 0, 4)?.try_into().unwrap()) as usize;
    let base = data_off + 4; // skip the resource's big-endian length
    let count = u32le(slice(rsrc, base, 4)?, 0) as usize;
    let mut out = Vec::with_capacity(size);
    for i in 0..count {
        let e = slice(rsrc, base + 4 + 8 * i, 8)?;
        let chunk = slice(rsrc, base + u32le(e, 0) as usize, u32le(e, 4) as usize)?;
        out.extend(zlib(chunk, CHUNK.min(size.saturating_sub(out.len())))?);
    }
    Ok(out)
}

/// LZVN/LZFSE resource fork: a table of little-endian chunk offsets; the first offset is the table size.
fn chunked(rsrc: &[u8], size: usize, f: fn(&[u8], usize) -> io::Result<Vec<u8>>) -> io::Result<Vec<u8>> {
    let table_len = u32le(slice(rsrc, 0, 4)?, 0) as usize;
    let n = (table_len / 4).saturating_sub(1);
    let mut out = Vec::with_capacity(size);
    for i in 0..n {
        let start = u32le(slice(rsrc, 4 * i, 4)?, 0) as usize;
        let end = u32le(slice(rsrc, 4 * i + 4, 4)?, 0) as usize;
        let chunk = slice(rsrc, start, end.checked_sub(start).ok_or_else(|| bad("bad chunk table"))?)?;
        out.extend(f(chunk, CHUNK.min(size.saturating_sub(out.len())))?);
    }
    Ok(out)
}
