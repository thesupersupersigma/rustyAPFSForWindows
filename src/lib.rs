//! Read-only APFS reader, built from Apple's "Apple File System Reference".

mod btree;
mod compress;
mod container;
mod crypto;
mod device;
#[cfg(windows)]
pub mod mount;
mod volume;

pub use container::Container;
pub use device::{Partition, apfs_partitions};
pub use volume::{DirEntry, File, Inode, Snapshot, Volume};

use std::io;

pub(crate) fn bad(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

pub(crate) fn u16le(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(b[off..off + 2].try_into().unwrap())
}
pub(crate) fn u32le(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}
pub(crate) fn u64le(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}

/// Bounds-checked slice, so a corrupt length field becomes an error instead of a panic.
pub(crate) fn slice(b: &[u8], off: usize, len: usize) -> io::Result<&[u8]> {
    b.get(off..off.checked_add(len).ok_or_else(|| bad("length overflow"))?)
        .ok_or_else(|| bad(format!("field out of bounds: {off}+{len} > {}", b.len())))
}
