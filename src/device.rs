//! Byte access to an image file, a whole disk, or one GPT partition of it.
//! Raw Windows disk devices (`\\.\PhysicalDriveN`) only accept sector-aligned I/O, so every access
//! here is widened to 4 KiB boundaries.

use crate::{bad, u32le, u64le};
use std::fs;
use std::io;
use std::path::Path;

const ALIGN: u64 = 4096;
/// GPT partition type for APFS, as stored on disk (mixed-endian GUID 7C3457EF-0000-11AA-AA11-00306543ECAC).
const APFS_GPT_TYPE: [u8; 16] = [0xef, 0x57, 0x34, 0x7c, 0, 0, 0xaa, 0x11, 0xaa, 0x11, 0, 0x30, 0x65, 0x43, 0xec, 0xac];

#[derive(Clone, Debug)]
pub struct Partition {
    /// Index in the GPT partition table (0-based).
    pub index: usize,
    pub offset: u64,
    pub size: u64,
    pub name: String,
}

pub(crate) struct Device {
    file: fs::File,
    base: u64,
}

impl Device {
    /// Opens an APFS container: a bare image/partition, or the `partition`-th APFS partition
    /// (default: the first) of a GPT disk.
    pub(crate) fn open(path: &Path, writable: bool, partition: Option<usize>) -> io::Result<Device> {
        let mut opts = fs::OpenOptions::new();
        opts.read(true).write(writable);
        // A writer shares only reading: a second writer (or another APFS driver) can't open the same
        // device and corrupt it with interleaved commits.
        #[cfg(windows)]
        if writable {
            std::os::windows::fs::OpenOptionsExt::share_mode(&mut opts, 1); // FILE_SHARE_READ
        }
        let file = opts.open(path).map_err(|e| {
            if writable && e.raw_os_error() == Some(32) {
                io::Error::new(io::ErrorKind::ResourceBusy, "the disk is already open for writing by another program")
            } else {
                e
            }
        })?;
        let mut dev = Device { file, base: 0 };
        let mut head = vec![0; 2 * ALIGN as usize];
        let n = dev.read_some(0, &mut head)?;
        if n >= 36 && &head[32..36] == b"NXSB" && partition.is_none() {
            return Ok(dev);
        }
        let parts = gpt_apfs_partitions(&dev)?;
        let want = partition.unwrap_or(0);
        let p = parts.get(want).ok_or_else(|| {
            bad(if parts.is_empty() {
                "no APFS container: not an APFS image and no APFS partition in a GPT".to_string()
            } else {
                format!("APFS partition {want} doesn't exist ({} found)", parts.len())
            })
        })?;
        dev.base = p.offset;
        Ok(dev)
    }

    pub(crate) fn read_at(&self, off: u64, buf: &mut [u8]) -> io::Result<()> {
        let (start, end) = (off / ALIGN * ALIGN, (off + buf.len() as u64).div_ceil(ALIGN) * ALIGN);
        if start == off && end == off + buf.len() as u64 {
            let n = self.read_some(off, buf)?;
            return if n == buf.len() { Ok(()) } else { Err(eof(off + n as u64)) };
        }
        let mut tmp = vec![0; (end - start) as usize];
        let n = self.read_some(start, &mut tmp)?;
        let (lo, hi) = ((off - start) as usize, (off - start) as usize + buf.len());
        // An image file may end mid-alignment-block; that's fine as long as the wanted bytes exist.
        if n < hi {
            return Err(eof(start + n as u64));
        }
        buf.copy_from_slice(&tmp[lo..hi]);
        Ok(())
    }

    /// Writes whole aligned blocks (all writers in this crate write full blocks).
    pub(crate) fn write_at(&self, off: u64, buf: &[u8]) -> io::Result<()> {
        if !off.is_multiple_of(ALIGN) || !(buf.len() as u64).is_multiple_of(ALIGN) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "unaligned device write"));
        }
        let mut done = 0;
        while done < buf.len() {
            let pos = self.base + off + done as u64;
            #[cfg(windows)]
            let n = std::os::windows::fs::FileExt::seek_write(&self.file, &buf[done..], pos)?;
            #[cfg(unix)]
            let n = std::os::unix::fs::FileExt::write_at(&self.file, &buf[done..], pos)?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::WriteZero, "device accepted no bytes"));
            }
            done += n;
        }
        Ok(())
    }

    /// Makes previous writes durable (FlushFileBuffers on Windows).
    pub(crate) fn flush(&self) -> io::Result<()> {
        self.file.sync_data()
    }

    /// Reads until `buf` is full or the end of the device; returns the byte count.
    fn read_some(&self, off: u64, buf: &mut [u8]) -> io::Result<usize> {
        let mut done = 0;
        while done < buf.len() {
            let pos = self.base + off + done as u64;
            #[cfg(windows)]
            let n = std::os::windows::fs::FileExt::seek_read(&self.file, &mut buf[done..], pos)?;
            #[cfg(unix)]
            let n = std::os::unix::fs::FileExt::read_at(&self.file, &mut buf[done..], pos)?;
            if n == 0 {
                break;
            }
            done += n;
        }
        Ok(done)
    }
}

fn eof(at: u64) -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, format!("read past end of device at byte {at}"))
}

/// Lists the APFS partitions of a GPT disk (empty if the device has no GPT).
pub fn apfs_partitions(path: impl AsRef<Path>) -> io::Result<Vec<Partition>> {
    gpt_apfs_partitions(&Device { file: fs::File::open(path)?, base: 0 })
}

fn gpt_apfs_partitions(dev: &Device) -> io::Result<Vec<Partition>> {
    // The GPT header sits in LBA 1; LBAs are 512 bytes or 4 KiB depending on the disk.
    for sector in [512u64, 4096] {
        let mut hdr = vec![0; 512];
        if dev.read_at(sector, &mut hdr).is_err() || &hdr[0..8] != b"EFI PART" {
            continue;
        }
        let (table_lba, count, entry_size) = (u64le(&hdr, 72), u32le(&hdr, 80) as usize, u32le(&hdr, 84) as usize);
        if !(128..=4096).contains(&entry_size) || count > 1024 {
            return Err(bad("implausible GPT header"));
        }
        let mut table = vec![0; count * entry_size];
        dev.read_at(table_lba * sector, &mut table)?;
        let mut out = vec![];
        for (index, e) in table.chunks_exact(entry_size).enumerate() {
            if e[0..16] != APFS_GPT_TYPE {
                continue;
            }
            let (first, last) = (u64le(e, 32), u64le(e, 40));
            let name: Vec<u16> = e[56..128].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
            let name = String::from_utf16_lossy(&name).trim_end_matches('\0').to_string();
            out.push(Partition { index, offset: first * sector, size: (last + 1 - first) * sector, name });
        }
        return Ok(out);
    }
    Ok(vec![])
}
