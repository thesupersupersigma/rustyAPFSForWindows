//! WinFsp mount: shows an APFS volume as a Windows drive letter or folder, read-only or read-write.
//!
//! Read-write mounts serialize every callback on one `Writer` behind a mutex and read through a fresh
//! `Writer::view` each time, so reads see uncommitted changes. Changes are committed on flush, on
//! cleanup of a handle that wrote, about once a second while dirty, and on unmount.

use crate::write::{Kind, Writer};
use crate::{Container, File, Inode, Volume};
use std::ffi::c_void;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use winfsp::filesystem::{
    DirBuffer, DirInfo, DirMarker, FileInfo, FileSecurity, FileSystemContext, ModificationDescriptor, OpenFileInfo,
    VolumeInfo, WideNameInfo,
};
use winfsp::host::{FileSystemHost, VolumeParams};
use winfsp::{FspError, U16CStr};

const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
const STATUS_OBJECT_NAME_INVALID: u32 = 0xC000_0033;
const STATUS_MEDIA_WRITE_PROTECTED: u32 = 0xC000_00A2;
const STATUS_END_OF_FILE: u32 = 0xC000_0011;
const STATUS_NOT_A_REPARSE_POINT: u32 = 0xC000_0275;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const STATUS_FILE_CORRUPT_ERROR: u32 = 0xC000_0102;
const STATUS_DIRECTORY_NOT_EMPTY: u32 = 0xC000_0101;
const STATUS_DISK_FULL: u32 = 0xC000_007F;
const STATUS_FILE_IS_A_DIRECTORY: u32 = 0xC000_00BA;
const STATUS_NOT_A_DIRECTORY: u32 = 0xC000_0103;
const STATUS_CANNOT_DELETE: u32 = 0xC000_0121;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;

const FILE_ATTRIBUTE_READONLY: u32 = 0x1;
const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x20;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const INVALID_FILE_ATTRIBUTES: u32 = u32::MAX;
const FILE_DIRECTORY_FILE: u32 = 0x1;
const FSP_CLEANUP_DELETE: u32 = 0x1;
const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;
const SYMLINK_FLAG_RELATIVE: u32 = 1;
const UF_HIDDEN: u32 = 0x8000;
const ROOT_DIR_INO: u64 = 2;
/// BSD "archived" flag, stored inverted as the Windows archive attribute ("needs archiving"), so files
/// macOS wrote show the attribute like new NTFS files do.
const SF_ARCHIVED: u32 = 0x1_0000;
const FSP_CLEANUP_SET_ARCHIVE_BIT: u32 = 0x10;

/// 100ns intervals between 1601-01-01 (FILETIME epoch) and 1970-01-01 (APFS epoch).
const FILETIME_UNIX_EPOCH: u64 = 116_444_736_000_000_000;
// Full access for everyone: the read-only volume flag (or the file's own read-only attribute) is what
// refuses writes, so Windows reports "write protected" instead of a misleading "access denied".
const SDDL: &str = "O:BAG:BAD:P(A;;FA;;;WD)";

fn nt(code: u32) -> FspError {
    FspError::NTSTATUS(code as i32)
}

fn fsp(e: io::Error) -> FspError {
    use io::ErrorKind::*;
    match e.kind() {
        NotFound => nt(STATUS_OBJECT_NAME_NOT_FOUND),
        AlreadyExists => nt(STATUS_OBJECT_NAME_COLLISION),
        DirectoryNotEmpty => nt(STATUS_DIRECTORY_NOT_EMPTY),
        ReadOnlyFilesystem => nt(STATUS_MEDIA_WRITE_PROTECTED),
        StorageFull => nt(STATUS_DISK_FULL),
        InvalidInput => nt(STATUS_OBJECT_NAME_INVALID),
        IsADirectory => nt(STATUS_FILE_IS_A_DIRECTORY),
        NotADirectory => nt(STATUS_NOT_A_DIRECTORY),
        Unsupported => nt(STATUS_NOT_SUPPORTED),
        PermissionDenied => nt(STATUS_ACCESS_DENIED),
        InvalidData | UnexpectedEof => nt(STATUS_FILE_CORRUPT_ERROR),
        _ => e.into(),
    }
}

/// One open handle. Inodes are re-read on every call, since a read-write mount changes them.
pub struct Handle {
    id: u64,
    path: Mutex<String>,
    /// Read-only mounts keep the opened data (compressed files decompress once).
    file: OnceLock<Result<File<'static>, io::ErrorKind>>,
    /// Read-write mounts cache decompressed data of compressed files here.
    unpacked: Mutex<Option<Arc<Vec<u8>>>>,
    wrote: AtomicBool,
    dir: DirBuffer,
}

impl Handle {
    fn new(id: u64, path: String) -> Handle {
        Handle {
            id,
            path: Mutex::new(path),
            file: OnceLock::new(),
            unpacked: Mutex::new(None),
            wrote: AtomicBool::new(false),
            dir: DirBuffer::new(),
        }
    }

    fn path(&self) -> String {
        self.path.lock().unwrap().clone()
    }
}

enum Backend {
    Ro(Volume<'static>),
    Rw { w: Arc<Mutex<Writer>>, v: usize },
}

pub struct ApfsFs {
    backend: Backend,
    /// False for volumes the writer refuses (snapshots, sealed, ...): served read-only from its view.
    writable: bool,
    block_size: u64,
    /// Container size, for read-only mounts (read-write ones ask the writer).
    total_size: u64,
    label: String,
    sd: Vec<u8>,
}

fn lock(w: &Mutex<Writer>) -> io::Result<MutexGuard<'_, Writer>> {
    // A panic mid-change leaves the writer half-updated; refuse to touch (or commit) it again.
    w.lock().map_err(|_| io::Error::other("the write engine crashed earlier; remount the volume"))
}

impl ApfsFs {
    fn rw(&self) -> bool {
        self.writable
    }

    /// Runs `f` on a view of the volume that includes uncommitted changes.
    fn with<R>(&self, f: impl FnOnce(&Volume) -> io::Result<R>) -> io::Result<R> {
        match &self.backend {
            Backend::Ro(vol) => f(vol),
            Backend::Rw { w, v } => {
                let w = lock(w)?;
                f(&w.view(*v)?)
            }
        }
    }

    /// Runs a change. `f` may read through `w.view(v)` first but must drop the view before writing.
    fn change<R>(&self, f: impl FnOnce(&mut Writer, usize) -> io::Result<R>) -> winfsp::Result<R> {
        match &self.backend {
            Backend::Ro(_) => Err(nt(STATUS_MEDIA_WRITE_PROTECTED)),
            Backend::Rw { w, v } => f(&mut *lock(w).map_err(fsp)?, *v).map_err(fsp),
        }
    }

    /// Size Windows should see: compressed files keep their real size in the decmpfs header.
    fn size_of(vol: &Volume, ino: &Inode) -> io::Result<u64> {
        if ino.is_symlink() {
            return Ok(0);
        }
        if ino.is_compressed()
            && let Some(h) = vol.xattr(ino.id, "com.apple.decmpfs")?
            && h.len() >= 16
        {
            return Ok(u64::from_le_bytes(h[8..16].try_into().unwrap()));
        }
        Ok(ino.size)
    }

    /// Resolves a symlink's target relative to the link's own path (APFS absolute targets are volume-relative).
    fn link_target(vol: &Volume, ino: &Inode, path: &str) -> io::Result<String> {
        let target = vol.readlink(ino)?;
        let mut parts: Vec<&str> =
            if target.starts_with('/') { vec![] } else { parent(path).split('/').filter(|p| !p.is_empty()).collect() };
        for p in target.split('/') {
            match p {
                "" | "." => {}
                ".." => {
                    parts.pop();
                }
                p => parts.push(p),
            }
        }
        Ok(parts.join("/"))
    }

    fn fill_info(&self, vol: &Volume, ino: &Inode, path: &str, out: &mut FileInfo) -> io::Result<()> {
        let mut attrs = if ino.is_dir() {
            FILE_ATTRIBUTE_DIRECTORY
        } else if !self.rw() {
            FILE_ATTRIBUTE_READONLY
        } else {
            (if ino.bsd_flags & SF_ARCHIVED == 0 { FILE_ATTRIBUTE_ARCHIVE } else { 0 })
                | if ino.mode & 0o200 == 0 { FILE_ATTRIBUTE_READONLY } else { 0 }
        };
        if ino.bsd_flags & UF_HIDDEN != 0
            || path.rsplit('/').next().is_some_and(|n| n.starts_with('.') && n != "." && n != "..")
        {
            attrs |= FILE_ATTRIBUTE_HIDDEN;
        }
        out.reparse_tag = 0;
        if ino.is_symlink() {
            attrs |= FILE_ATTRIBUTE_REPARSE_POINT;
            out.reparse_tag = IO_REPARSE_TAG_SYMLINK;
            // Windows needs to know up front whether a link points at a directory.
            let target = Self::link_target(vol, ino, path).and_then(|t| vol.lookup(&t));
            if target.is_ok_and(|t| t.is_dir()) {
                attrs = (attrs & !FILE_ATTRIBUTE_READONLY) | FILE_ATTRIBUTE_DIRECTORY;
            }
        }
        let size = Self::size_of(vol, ino)?;
        out.file_attributes = attrs;
        out.file_size = size;
        out.allocation_size = size.div_ceil(self.block_size) * self.block_size;
        out.creation_time = filetime(ino.create_time);
        out.last_access_time = filetime(ino.access_time);
        out.last_write_time = filetime(ino.mod_time);
        out.change_time = filetime(ino.change_time);
        out.index_number = ino.id;
        out.hard_links = 0; // winfsp-rs: unimplemented, must be 0
        out.ea_size = 0;
        Ok(())
    }

    /// Fills `out` for the handle's current state.
    fn info(&self, h: &Handle, out: &mut FileInfo) -> winfsp::Result<()> {
        self.with(|vol| self.fill_info(vol, &vol.inode(h.id)?, &h.path(), out)).map_err(fsp)
    }

    fn copy_sd(&self, buf: Option<&mut [c_void]>) -> u64 {
        if let Some(buf) = buf
            && buf.len() >= self.sd.len()
        {
            // SAFETY: buf has at least sd.len() bytes.
            unsafe { buf.as_mut_ptr().cast::<u8>().copy_from_nonoverlapping(self.sd.as_ptr(), self.sd.len()) };
        }
        self.sd.len() as u64
    }

    /// Builds an IO_REPARSE_TAG_SYMLINK reparse buffer with a relative target.
    fn reparse_data(vol: &Volume, ino: &Inode, path: &str, buf: &mut [u8]) -> winfsp::Result<u64> {
        if !ino.is_symlink() {
            return Err(nt(STATUS_NOT_A_REPARSE_POINT));
        }
        let target = vol.readlink(ino).map_err(fsp)?;
        // Absolute APFS targets are relative to the volume root; climb up from the link's directory.
        let rel = match target.strip_prefix('/') {
            Some(rest) => {
                "../".repeat(parent(path).split('/').filter(|p| !p.is_empty()).count()) + rest.trim_start_matches('/')
            }
            None => target,
        };
        let name: Vec<u16> = rel.replace('/', "\\").encode_utf16().collect();
        let name_bytes = name.len() * 2;
        // REPARSE_DATA_BUFFER header (8) + symlink header (12) + substitute name + print name.
        let total = 20 + 2 * name_bytes;
        if buf.len() < total {
            return Err(nt(STATUS_BUFFER_TOO_SMALL));
        }
        let mut w = Vec::with_capacity(total);
        w.extend_from_slice(&IO_REPARSE_TAG_SYMLINK.to_le_bytes());
        w.extend_from_slice(&((total - 8) as u16).to_le_bytes());
        w.extend_from_slice(&0u16.to_le_bytes());
        for v in [0, name_bytes, name_bytes, name_bytes] {
            w.extend_from_slice(&(v as u16).to_le_bytes()); // substitute off/len, print off/len
        }
        w.extend_from_slice(&SYMLINK_FLAG_RELATIVE.to_le_bytes());
        for _ in 0..2 {
            w.extend(name.iter().flat_map(|c| c.to_le_bytes()));
        }
        buf[..total].copy_from_slice(&w);
        Ok(total as u64)
    }
}

/// Applies Windows attributes: read-only clears/restores the write bits, hidden maps to UF_HIDDEN.
fn apply_attributes(w: &mut Writer, v: usize, id: u64, attrs: u32) -> io::Result<()> {
    let ino = w.view(v)?.inode(id)?;
    if !ino.is_dir() {
        let perm = ino.mode & 0o7777;
        let want = if attrs & FILE_ATTRIBUTE_READONLY != 0 { perm & !0o222 } else { perm | 0o200 };
        if want != perm {
            w.set_mode(v, id, want)?;
        }
    }
    let mut flags =
        if attrs & FILE_ATTRIBUTE_HIDDEN != 0 { ino.bsd_flags | UF_HIDDEN } else { ino.bsd_flags & !UF_HIDDEN };
    if !ino.is_dir() {
        flags = if attrs & FILE_ATTRIBUTE_ARCHIVE != 0 { flags & !SF_ARCHIVED } else { flags | SF_ARCHIVED };
    }
    if flags != ino.bsd_flags {
        w.set_bsd_flags(v, id, flags)?;
    }
    Ok(())
}

/// Looks `path` up and returns its inode plus the path as spelled on disk (case and normalization).
fn resolve(vol: &Volume, path: &str) -> io::Result<(Inode, String)> {
    let mut id = ROOT_DIR_INO;
    let mut stored = String::new();
    for part in path.split('/').filter(|p| !p.is_empty()) {
        let (next, name) = vol.find_child_named(id, part)?.ok_or(io::ErrorKind::NotFound)?;
        id = next;
        stored.push('/');
        stored.push_str(&name);
    }
    Ok((vol.inode(id)?, if stored.is_empty() { "/".into() } else { stored }))
}

/// Reports the on-disk spelling, so Windows shows stored names instead of the case the caller typed.
fn set_normalized(info: &mut OpenFileInfo, stored: &str) {
    let wide: Vec<u16> = stored.replace('/', "\\").encode_utf16().collect();
    info.set_normalized_name(&wide, None);
}

fn filetime(ns: u64) -> u64 {
    ns / 100 + FILETIME_UNIX_EPOCH
}

fn unix_ns(ft: u64) -> u64 {
    ft.saturating_sub(FILETIME_UNIX_EPOCH).saturating_mul(100)
}

fn parent(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(p, _)| p)
}

/// Splits `/a/b` into (`/a`, `b`).
fn split(path: &str) -> (&str, &str) {
    match path.rsplit_once('/') {
        Some(("", name)) => ("/", name),
        Some((dir, name)) => (dir, name),
        None => ("/", path),
    }
}

/// WinFsp paths look like `\dir\file`; ours look like `/dir/file`.
fn to_path(name: &U16CStr) -> String {
    let p = name.to_string_lossy().replace('\\', "/");
    if p.is_empty() { "/".into() } else { p }
}

fn join(dir: &str, name: &str) -> String {
    if dir == "/" { format!("/{name}") } else { format!("{dir}/{name}") }
}

impl FileSystemContext for ApfsFs {
    type FileContext = Handle;

    fn get_security_by_name(
        &self,
        file_name: &U16CStr,
        security_descriptor: Option<&mut [c_void]>,
        reparse_point_resolver: impl FnOnce(&U16CStr) -> Option<FileSecurity>,
    ) -> winfsp::Result<FileSecurity> {
        if let Some(sec) = reparse_point_resolver(file_name) {
            return Ok(sec);
        }
        let path = to_path(file_name);
        let mut info = FileInfo::default();
        self.with(|vol| self.fill_info(vol, &vol.lookup(&path)?, &path, &mut info)).map_err(fsp)?;
        Ok(FileSecurity {
            reparse: false,
            sz_security_descriptor: self.copy_sd(security_descriptor),
            attributes: info.file_attributes,
        })
    }

    fn open(
        &self,
        file_name: &U16CStr,
        _create_options: u32,
        _granted_access: u32,
        file_info: &mut OpenFileInfo,
    ) -> winfsp::Result<Handle> {
        let (id, stored) = self
            .with(|vol| {
                let (ino, stored) = resolve(vol, &to_path(file_name))?;
                self.fill_info(vol, &ino, &stored, file_info.as_mut())?;
                Ok((ino.id, stored))
            })
            .map_err(fsp)?;
        set_normalized(file_info, &stored);
        Ok(Handle::new(id, stored))
    }

    fn close(&self, _context: Handle) {}

    #[allow(clippy::too_many_arguments)]
    fn create(
        &self,
        file_name: &U16CStr,
        create_options: u32,
        _granted_access: u32,
        file_attributes: u32,
        _security_descriptor: Option<&[c_void]>,
        _allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        extra_buffer_is_reparse_point: bool,
        file_info: &mut OpenFileInfo,
    ) -> winfsp::Result<Handle> {
        if extra_buffer_is_reparse_point {
            return Err(nt(STATUS_NOT_SUPPORTED)); // shortcut: creating symlinks from Windows isn't supported
        }
        let path = to_path(file_name);
        let (dir, name) = split(&path);
        let id = self.change(|w, v| {
            let parent = w.view(v)?.lookup(dir)?;
            if !parent.is_dir() {
                return Err(io::ErrorKind::NotADirectory.into());
            }
            let (kind, perm) =
                if create_options & FILE_DIRECTORY_FILE != 0 { (Kind::Dir, 0o755) } else { (Kind::File, 0o644) };
            let id = w.create(v, parent.id, name, kind, perm)?;
            apply_attributes(w, v, id, file_attributes | FILE_ATTRIBUTE_ARCHIVE)?;
            Ok(id)
        })?;
        let stored = self.with(|vol| resolve(vol, &path).map(|(_, s)| s)).map_err(fsp)?;
        set_normalized(file_info, &stored);
        let h = Handle::new(id, stored);
        self.info(&h, file_info.as_mut())?;
        Ok(h)
    }

    fn overwrite(
        &self,
        context: &Handle,
        file_attributes: u32,
        replace_file_attributes: bool,
        _allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        self.change(|w, v| {
            w.set_size(v, context.id, 0)?;
            let ino = w.view(v)?.inode(context.id)?;
            let mut attrs = file_attributes | FILE_ATTRIBUTE_ARCHIVE;
            if !replace_file_attributes {
                // Keep the current read-only/hidden bits and add the requested ones.
                if ino.mode & 0o200 == 0 {
                    attrs |= FILE_ATTRIBUTE_READONLY;
                }
                if ino.bsd_flags & UF_HIDDEN != 0 {
                    attrs |= FILE_ATTRIBUTE_HIDDEN;
                }
            }
            apply_attributes(w, v, context.id, attrs)
        })?;
        context.wrote.store(true, Ordering::Relaxed);
        *context.unpacked.lock().unwrap() = None;
        self.info(context, file_info)
    }

    fn cleanup(&self, context: &Handle, file_name: Option<&U16CStr>, flags: u32) {
        let Backend::Rw { w, v } = &self.backend else { return };
        let Ok(mut w) = lock(w) else { return };
        if flags & FSP_CLEANUP_DELETE != 0 {
            let path = file_name.map_or_else(|| context.path(), to_path);
            let (dir, name) = split(&path);
            let res = w.view(*v).and_then(|vol| vol.lookup(dir)).and_then(|p| w.remove(*v, p.id, name));
            if let Err(e) = res {
                eprintln!("delete {path}: {e}");
            }
        }
        if flags & FSP_CLEANUP_SET_ARCHIVE_BIT != 0 && flags & FSP_CLEANUP_DELETE == 0 {
            let set = w.view(*v).and_then(|vol| vol.inode(context.id)).and_then(|ino| {
                if ino.is_dir() || ino.bsd_flags & SF_ARCHIVED == 0 {
                    Ok(())
                } else {
                    w.set_bsd_flags(*v, ino.id, ino.bsd_flags & !SF_ARCHIVED)
                }
            });
            if let Err(e) = set {
                eprintln!("archive bit: {e}");
            }
        }
        if (flags & FSP_CLEANUP_DELETE != 0 || context.wrote.load(Ordering::Relaxed))
            && let Err(e) = w.commit()
        {
            eprintln!("commit failed: {e}");
        }
    }

    fn flush(&self, context: Option<&Handle>, file_info: &mut FileInfo) -> winfsp::Result<()> {
        if let Backend::Rw { w, .. } = &self.backend {
            lock(w).and_then(|mut w| w.commit()).map_err(fsp)?;
        }
        match context {
            Some(h) => self.info(h, file_info),
            None => Ok(()),
        }
    }

    fn rename(
        &self,
        context: &Handle,
        file_name: &U16CStr,
        new_file_name: &U16CStr,
        replace_if_exists: bool,
    ) -> winfsp::Result<()> {
        let (from, to) = (to_path(file_name), to_path(new_file_name));
        let ((sd, sn), (dd, dn)) = (split(&from), split(&to));
        self.change(|w, v| {
            let (sp, dp) = {
                let vol = w.view(v)?;
                let src = vol.lookup(&from)?.id;
                if replace_if_exists && vol.lookup(&to).is_ok_and(|t| t.is_dir() && t.id != src) {
                    // Windows never lets a rename replace a directory.
                    return Err(io::ErrorKind::PermissionDenied.into());
                }
                (vol.lookup(sd)?.id, vol.lookup(dd)?.id)
            };
            w.rename(v, sp, sn, dp, dn, replace_if_exists)
        })?;
        // shortcut: open handles of files inside a renamed directory keep their old path; it's only used
        // for the hidden-dotfile and symlink-target checks.
        *context.path.lock().unwrap() = to;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn set_basic_info(
        &self,
        context: &Handle,
        file_attributes: u32,
        creation_time: u64,
        last_access_time: u64,
        last_write_time: u64,
        last_change_time: u64,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        let t = |ft: u64| (ft != 0).then(|| unix_ns(ft));
        self.change(|w, v| {
            if file_attributes != INVALID_FILE_ATTRIBUTES {
                apply_attributes(w, v, context.id, file_attributes)?;
            }
            let times = [creation_time, last_write_time, last_change_time, last_access_time];
            if times.iter().any(|&ft| ft != 0) {
                w.set_times(
                    v,
                    context.id,
                    t(creation_time),
                    t(last_write_time),
                    t(last_change_time),
                    t(last_access_time),
                )?;
            }
            Ok(())
        })?;
        self.info(context, file_info)
    }

    fn set_delete(&self, context: &Handle, _file_name: &U16CStr, delete_file: bool) -> winfsp::Result<()> {
        if !delete_file {
            return Ok(());
        }
        if !self.rw() {
            return Err(nt(STATUS_MEDIA_WRITE_PROTECTED));
        }
        let (dir, readonly, children) = self
            .with(|vol| {
                let ino = vol.inode(context.id)?;
                let children = if ino.is_dir() { !vol.read_dir(ino.id)?.is_empty() } else { false };
                Ok((ino.is_dir(), ino.mode & 0o200 == 0, children))
            })
            .map_err(fsp)?;
        if children {
            return Err(nt(STATUS_DIRECTORY_NOT_EMPTY));
        }
        if readonly && !dir {
            return Err(nt(STATUS_CANNOT_DELETE));
        }
        Ok(())
    }

    fn set_file_size(
        &self,
        context: &Handle,
        new_size: u64,
        set_allocation_size: bool,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        self.change(|w, v| {
            let ino = w.view(v)?.inode(context.id)?;
            let size = ApfsFs::size_of(&w.view(v)?, &ino)?;
            // Allocation size only matters when it cuts into the data; it never grows the file.
            if !set_allocation_size || new_size < size {
                w.set_size(v, context.id, new_size)?;
            }
            Ok(())
        })?;
        context.wrote.store(true, Ordering::Relaxed);
        *context.unpacked.lock().unwrap() = None;
        self.info(context, file_info)
    }

    fn write(
        &self,
        context: &Handle,
        buffer: &[u8],
        offset: u64,
        write_to_eof: bool,
        constrained_io: bool,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<u32> {
        let n = self.change(|w, v| {
            let size = {
                let vol = w.view(v)?;
                ApfsFs::size_of(&vol, &vol.inode(context.id)?)?
            };
            let off = if write_to_eof { size } else { offset };
            let mut data = buffer;
            if constrained_io {
                // Paging I/O must not extend the file.
                if off >= size {
                    return Ok(0);
                }
                data = &data[..data.len().min((size - off) as usize)];
            }
            w.write_at(v, context.id, off, data)?;
            Ok(data.len())
        })?;
        context.wrote.store(true, Ordering::Relaxed);
        *context.unpacked.lock().unwrap() = None;
        self.info(context, file_info)?;
        Ok(n as u32)
    }

    fn set_volume_label(&self, _: &U16CStr, _: &mut VolumeInfo) -> winfsp::Result<()> {
        Err(nt(if self.rw() { STATUS_NOT_SUPPORTED } else { STATUS_MEDIA_WRITE_PROTECTED }))
    }

    fn get_file_info(&self, context: &Handle, file_info: &mut FileInfo) -> winfsp::Result<()> {
        self.info(context, file_info)
    }

    fn get_security(&self, _context: &Handle, security_descriptor: Option<&mut [c_void]>) -> winfsp::Result<u64> {
        Ok(self.copy_sd(security_descriptor))
    }

    fn set_security(&self, _: &Handle, _: u32, _: ModificationDescriptor) -> winfsp::Result<()> {
        // shortcut: APFS permissions aren't mapped to Windows ACLs; accept and ignore so copies don't fail.
        if self.rw() { Ok(()) } else { Err(nt(STATUS_MEDIA_WRITE_PROTECTED)) }
    }

    fn read_directory(
        &self,
        context: &Handle,
        _pattern: Option<&U16CStr>,
        marker: DirMarker,
        buffer: &mut [u8],
    ) -> winfsp::Result<u32> {
        // A fresh enumeration refills the buffer; WinFsp sorts it and resumes from the marker itself.
        if marker.is_none() {
            let lock = context.dir.acquire(true, None)?;
            let path = context.path();
            self.with(|vol| {
                let me = vol.inode(context.id)?;
                let mut di: DirInfo = DirInfo::new();
                let put = |di: &mut DirInfo, name: &str| -> io::Result<()> {
                    di.set_name(name).map_err(|e| io::Error::other(format!("{e:?}")))?;
                    lock.write(di).map_err(|e| io::Error::other(format!("{e:?}")))
                };
                if path != "/" {
                    let up = vol.inode(me.parent_id)?;
                    for (name, ino, p) in [(".", &me, path.as_str()), ("..", &up, parent(&path))] {
                        di.reset();
                        self.fill_info(vol, ino, p, di.file_info_mut())?;
                        put(&mut di, name)?;
                    }
                }
                for e in vol.read_dir(me.id)? {
                    let ino = vol.inode(e.id)?;
                    di.reset();
                    self.fill_info(vol, &ino, &join(&path, &e.name), di.file_info_mut())?;
                    put(&mut di, &e.name)?;
                }
                Ok(())
            })
            .map_err(fsp)?;
        }
        Ok(context.dir.read(marker, buffer))
    }

    fn read(&self, context: &Handle, buffer: &mut [u8], offset: u64) -> winfsp::Result<u32> {
        let n = match &self.backend {
            Backend::Ro(vol) => {
                let file =
                    context.file.get_or_init(|| vol.inode(context.id).and_then(|i| vol.open(&i)).map_err(|e| e.kind()));
                let file = file.as_ref().map_err(|&k| fsp(k.into()))?;
                if offset >= file.size {
                    return Err(nt(STATUS_END_OF_FILE));
                }
                file.read_at(offset, buffer).map_err(fsp)?
            }
            Backend::Rw { .. } => self
                .with(|vol| {
                    let ino = vol.inode(context.id)?;
                    if ino.is_dir() {
                        return Err(io::ErrorKind::IsADirectory.into());
                    }
                    if !ino.is_compressed() {
                        return vol.open(&ino)?.read_at(offset, buffer);
                    }
                    let mut cache = context.unpacked.lock().unwrap();
                    let data = match &*cache {
                        Some(d) => d.clone(),
                        None => cache.insert(Arc::new(vol.open(&ino)?.read_all()?)).clone(),
                    };
                    let s = (offset.min(data.len() as u64)) as usize;
                    let n = buffer.len().min(data.len() - s);
                    buffer[..n].copy_from_slice(&data[s..s + n]);
                    Ok(n)
                })
                .map_err(fsp)?,
        };
        if n == 0 && !buffer.is_empty() {
            return Err(nt(STATUS_END_OF_FILE));
        }
        Ok(n as u32)
    }

    fn get_volume_info(&self, out: &mut VolumeInfo) -> winfsp::Result<()> {
        match &self.backend {
            Backend::Ro(_) => {
                out.total_size = self.total_size;
                out.free_size = 0; // shortcut: read-only mounts don't load the space manager
            }
            Backend::Rw { w, .. } => {
                let w = lock(w).map_err(fsp)?;
                out.total_size = w.total_blocks() * self.block_size;
                out.free_size = w.free_blocks() * self.block_size;
            }
        }
        out.set_volume_label(&self.label);
        Ok(())
    }

    fn get_reparse_point_by_name(
        &self,
        file_name: &U16CStr,
        _is_directory: bool,
        buffer: &mut [u8],
    ) -> winfsp::Result<u64> {
        let path = to_path(file_name);
        let ino = self.with(|vol| vol.lookup(&path)).map_err(fsp)?;
        match &self.backend {
            Backend::Ro(vol) => Self::reparse_data(vol, &ino, &path, buffer),
            Backend::Rw { w, v } => {
                Self::reparse_data(&lock(w).map_err(fsp)?.view(*v).map_err(fsp)?, &ino, &path, buffer)
            }
        }
    }

    fn get_reparse_point(&self, context: &Handle, _file_name: &U16CStr, buffer: &mut [u8]) -> winfsp::Result<u64> {
        let path = context.path();
        match &self.backend {
            Backend::Ro(vol) => Self::reparse_data(vol, &vol.inode(context.id).map_err(fsp)?, &path, buffer),
            Backend::Rw { w, v } => {
                let w = lock(w).map_err(fsp)?;
                let vol = w.view(*v).map_err(fsp)?;
                Self::reparse_data(&vol, &vol.inode(context.id).map_err(fsp)?, &path, buffer)
            }
        }
    }

    fn set_reparse_point(&self, _: &Handle, _: &U16CStr, _: &[u8]) -> winfsp::Result<()> {
        Err(nt(if self.rw() { STATUS_NOT_SUPPORTED } else { STATUS_MEDIA_WRITE_PROTECTED }))
    }

    fn delete_reparse_point(&self, _: &Handle, _: &U16CStr, _: &[u8]) -> winfsp::Result<()> {
        Err(nt(if self.rw() { STATUS_ACCESS_DENIED } else { STATUS_MEDIA_WRITE_PROTECTED }))
    }
}

static STOP: AtomicBool = AtomicBool::new(false);

#[link(name = "advapi32")]
unsafe extern "system" {
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        s: *const u16,
        rev: u32,
        sd: *mut *mut c_void,
        len: *mut u32,
    ) -> i32;
    fn RegGetValueW(
        key: isize,
        sub: *const u16,
        value: *const u16,
        flags: u32,
        ty: *mut u32,
        data: *mut c_void,
        len: *mut u32,
    ) -> i32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn LoadLibraryW(name: *const u16) -> *mut c_void;
    fn LocalFree(mem: *mut c_void) -> *mut c_void;
    fn SetConsoleCtrlHandler(handler: Option<unsafe extern "system" fn(u32) -> i32>, add: i32) -> i32;
}

unsafe extern "system" fn on_ctrl(_event: u32) -> i32 {
    STOP.store(true, Ordering::SeqCst);
    1
}

fn failed<E: std::fmt::Debug>(what: &'static str) -> impl Fn(E) -> io::Error {
    move |e| io::Error::other(format!("{what} failed: {e:?}"))
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

fn security_descriptor() -> io::Result<Vec<u8>> {
    let (mut sd, mut len) = (std::ptr::null_mut(), 0u32);
    // SAFETY: valid NUL-terminated SDDL, out-pointers to locals; LocalFree releases the API's allocation.
    unsafe {
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(wide(SDDL).as_ptr(), 1, &mut sd, &mut len) == 0 {
            return Err(io::Error::last_os_error());
        }
        let out = std::slice::from_raw_parts(sd.cast::<u8>(), len as usize).to_vec();
        LocalFree(sd);
        Ok(out)
    }
}

/// The crate only searches the normal DLL path; WinFsp's installer doesn't add its bin folder to PATH,
/// so load the DLL from the install directory recorded in the registry first.
fn preload_winfsp() {
    const HKEY_LOCAL_MACHINE: isize = 0x8000_0002u32 as i32 as isize;
    const RRF_RT_REG_SZ: u32 = 0x2;
    let mut buf = [0u16; 260];
    let mut len = (buf.len() * 2) as u32;
    // SAFETY: buffer and length describe a valid local array.
    let ok = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            wide("SOFTWARE\\WOW6432Node\\WinFsp").as_ptr(),
            wide("InstallDir").as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            buf.as_mut_ptr().cast(),
            &mut len,
        )
    } == 0;
    if ok {
        let dir = String::from_utf16_lossy(&buf[..(len as usize / 2).saturating_sub(1)]);
        // SAFETY: NUL-terminated path; a failed load is fine, winfsp_init reports it.
        unsafe { LoadLibraryW(wide(&format!("{}\\bin\\winfsp-x64.dll", dir.trim_end_matches('\\'))).as_ptr()) };
    }
}

/// A volume ready to mount: the file system plus what WinFsp needs to know about it.
pub struct Mount {
    fs: ApfsFs,
    serial: u32,
    case_insensitive: bool,
    pub mountpoint: String,
}

fn start(m: Mount) -> io::Result<FileSystemHost<ApfsFs>> {
    let rw = m.fs.rw();
    let mut params = VolumeParams::new();
    params
        .filesystem_name("APFS")
        .sector_size(512)
        .sectors_per_allocation_unit((m.fs.block_size / 512) as u16)
        .max_component_length(255)
        .volume_serial_number(m.serial)
        .case_sensitive_search(!m.case_insensitive)
        .case_preserved_names(true)
        .unicode_on_disk(true)
        .persistent_acls(true)
        .reparse_points(true)
        .read_only_volume(!rw)
        .post_cleanup_when_modified_only(true)
        // Read-only data never changes under us, so let Windows cache it; read-write must stay fresh.
        .file_info_timeout(if rw { 0 } else { u32::MAX });
    let mut host: FileSystemHost<ApfsFs> =
        FileSystemHost::new(params, m.fs).map_err(failed("creating the file system"))?;
    host.mount(&m.mountpoint).map_err(failed("mounting"))?;
    host.start().map_err(failed("starting the dispatcher"))?;
    println!("mounted at {} ({})", m.mountpoint, if rw { "read-write" } else { "read-only" });
    Ok(host)
}

/// Mounts every volume in `mounts` and serves them until Ctrl+C, committing each writer about once a
/// second while it has changes and once more on the way out.
pub fn serve(mounts: Vec<Mount>) -> io::Result<()> {
    preload_winfsp();
    winfsp::winfsp_init().map_err(|e| io::Error::other(format!("WinFsp is not installed or failed to load: {e:?}")))?;
    let mut writers: Vec<Arc<Mutex<Writer>>> = vec![];
    for m in &mounts {
        if let Backend::Rw { w, .. } = &m.fs.backend
            && !writers.iter().any(|x| Arc::ptr_eq(x, w))
        {
            writers.push(w.clone());
        }
    }
    let mut hosts = vec![];
    for m in mounts {
        let mp = m.mountpoint.clone();
        match start(m) {
            Ok(h) => hosts.push(h),
            Err(e) => eprintln!("{mp}: {e}"),
        }
    }
    if hosts.is_empty() {
        return Err(io::Error::other("nothing could be mounted"));
    }
    // SAFETY: registers a plain function; it only touches an atomic.
    unsafe { SetConsoleCtrlHandler(Some(on_ctrl), 1) };
    println!("press Ctrl+C to unmount");
    let mut ticks = 0;
    while !STOP.load(Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::from_millis(200));
        ticks += 1;
        if ticks % 5 == 0 {
            for w in &writers {
                if let Ok(mut w) = lock(w)
                    && w.has_changes()
                    && let Err(e) = w.commit()
                {
                    eprintln!("commit failed: {e}");
                }
            }
        }
    }
    for mut h in hosts {
        h.stop();
        h.unmount();
    }
    let mut result = Ok(());
    for w in &writers {
        if let Err(e) = lock(w).and_then(|mut w| w.commit()) {
            result = Err(e);
        }
    }
    println!("unmounted");
    result
}

/// Prepares `vol` for a read-only mount at `mountpoint` (a drive like `X:` or a new folder path).
pub fn read_only(c: &'static Container, vol: Volume<'static>, mountpoint: &str) -> io::Result<Mount> {
    vol.root()?; // fail early on volumes we can't read (e.g. encrypted)
    let serial = u32::from_le_bytes(vol.superblock[240..244].try_into().unwrap());
    let case_insensitive = vol.case_insensitive();
    let total_size = u64::from_le_bytes(c.superblock[40..48].try_into().unwrap()) * c.block_size; // nx_block_count
    let fs = ApfsFs {
        writable: false,
        block_size: c.block_size,
        total_size,
        label: vol.name.clone(),
        backend: Backend::Ro(vol),
        sd: security_descriptor()?,
    };
    Ok(Mount { fs, serial, case_insensitive, mountpoint: mountpoint.to_string() })
}

/// Prepares volume `v` of a shared writer; it is writable unless the writer refuses that volume.
pub fn through_writer(w: &Arc<Mutex<Writer>>, v: usize, mountpoint: &str) -> io::Result<Mount> {
    let guard = lock(w)?;
    let (serial, case_insensitive, label) = {
        let vol = guard.view(v)?;
        vol.root()?;
        (u32::from_le_bytes(vol.superblock[240..244].try_into().unwrap()), vol.case_insensitive(), vol.name.clone())
    };
    let fs = ApfsFs {
        writable: guard.read_only_reason(v).is_none(),
        block_size: guard.block_size(),
        total_size: 0,
        label,
        backend: Backend::Rw { w: w.clone(), v },
        sd: security_descriptor()?,
    };
    Ok(Mount { fs, serial, case_insensitive, mountpoint: mountpoint.to_string() })
}

/// Mounts `vol` read-only at `mountpoint` until Ctrl+C.
pub fn mount(c: &'static Container, vol: Volume<'static>, mountpoint: &str) -> io::Result<()> {
    serve(vec![read_only(c, vol, mountpoint)?])
}

/// Mounts volume `v` of `w` read-write at `mountpoint` until Ctrl+C, committing changes as it goes.
pub fn mount_rw(w: Writer, v: usize, mountpoint: &str) -> io::Result<()> {
    serve(vec![through_writer(&Arc::new(Mutex::new(w)), v, mountpoint)?])
}

/// Drive letters not in use, from Z: down (so they don't collide with removable drives Windows adds).
pub fn free_drive_letters() -> Vec<String> {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetLogicalDrives() -> u32;
    }
    // SAFETY: no arguments; returns a bitmask of drive letters in use.
    let used = unsafe { GetLogicalDrives() };
    (b'D'..=b'Z').rev().filter(|&c| used & (1 << (c - b'A')) == 0).map(|c| format!("{}:", c as char)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symlinks_become_relative_reparse_points() {
        let img = concat!(env!("CARGO_MANIFEST_DIR"), "/ignored/testdata/case_insensitive.bin");
        let c: &'static Container = Box::leak(Box::new(Container::open(img).unwrap()));
        let vol = c.volumes().unwrap().remove(0);

        let link = vol.lookup("/symlink-dir").unwrap();
        assert_eq!(ApfsFs::link_target(&vol, &link, "/symlink-dir").unwrap(), "dir");

        let link = vol.lookup("/symlink-file").unwrap();
        let mut buf = [0u8; 256];
        let n = ApfsFs::reparse_data(&vol, &link, "/symlink-file", &mut buf).unwrap() as usize;
        let name: Vec<u16> = "dir\\file".encode_utf16().collect();
        assert_eq!(n, 20 + 4 * name.len());
        assert_eq!(u32::from_le_bytes(buf[0..4].try_into().unwrap()), IO_REPARSE_TAG_SYMLINK);
        assert_eq!(u16::from_le_bytes(buf[4..6].try_into().unwrap()) as usize, n - 8);
        assert_eq!(u32::from_le_bytes(buf[16..20].try_into().unwrap()), SYMLINK_FLAG_RELATIVE);
        let sub: Vec<u16> = buf[20..20 + 2 * name.len()].chunks(2).map(|b| u16::from_le_bytes([b[0], b[1]])).collect();
        assert_eq!(sub, name);

        let file = vol.lookup("/dir/file").unwrap();
        assert!(ApfsFs::reparse_data(&vol, &file, "/dir/file", &mut buf).is_err());
    }

    #[test]
    fn path_and_time_helpers() {
        assert_eq!(split("/a"), ("/", "a"));
        assert_eq!(split("/a/b/c"), ("/a/b", "c"));
        assert_eq!(unix_ns(filetime(1_700_000_000_123_456_700)), 1_700_000_000_123_456_700);
        assert_eq!(unix_ns(5), 0); // before 1970 clamps instead of wrapping
    }
}
