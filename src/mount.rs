//! Read-only WinFsp mount: shows an APFS volume as a Windows drive letter or folder.

use crate::{Container, File, Inode, Volume};
use std::ffi::c_void;
use std::io;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use winfsp::filesystem::{
    DirBuffer, DirInfo, DirMarker, FileInfo, FileSecurity, FileSystemContext, OpenFileInfo, VolumeInfo, WideNameInfo,
};
use winfsp::host::{FileSystemHost, VolumeParams};
use winfsp::{FspError, U16CStr};

const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_MEDIA_WRITE_PROTECTED: u32 = 0xC000_00A2;
const STATUS_END_OF_FILE: u32 = 0xC000_0011;
const STATUS_NOT_A_REPARSE_POINT: u32 = 0xC000_0275;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const STATUS_FILE_CORRUPT_ERROR: u32 = 0xC000_0102;

const FILE_ATTRIBUTE_READONLY: u32 = 0x1;
const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;
const SYMLINK_FLAG_RELATIVE: u32 = 1;

/// 100ns intervals between 1601-01-01 (FILETIME epoch) and 1970-01-01 (APFS epoch).
const FILETIME_UNIX_EPOCH: u64 = 116_444_736_000_000_000;
// Full access for everyone: the read-only volume flag is what refuses writes, so Windows reports
// "write protected" instead of a misleading "access denied".
const SDDL: &str = "O:BAG:BAD:P(A;;FA;;;WD)";

fn nt(code: u32) -> FspError {
    FspError::NTSTATUS(code as i32)
}

fn fsp(e: io::Error) -> FspError {
    match e.kind() {
        io::ErrorKind::NotFound => nt(STATUS_OBJECT_NAME_NOT_FOUND),
        io::ErrorKind::Unsupported => nt(STATUS_NOT_SUPPORTED),
        io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof => nt(STATUS_FILE_CORRUPT_ERROR),
        _ => e.into(),
    }
}

/// One open handle. File data is opened lazily: compressed files decompress on open,
/// and most handles only ever ask for metadata.
pub struct Handle {
    ino: Inode,
    path: String,
    file: OnceLock<Result<File<'static>, io::ErrorKind>>,
    dir: DirBuffer,
}

pub struct ApfsFs {
    c: &'static Container,
    vol: Volume<'static>,
    sd: Vec<u8>,
}

impl ApfsFs {
    /// Size Windows should see: compressed files keep their real size in the decmpfs header.
    fn size_of(&self, ino: &Inode) -> io::Result<u64> {
        if ino.is_symlink() {
            return Ok(0);
        }
        if ino.is_compressed()
            && let Some(h) = self.vol.xattr(ino.id, "com.apple.decmpfs")?
            && h.len() >= 16
        {
            return Ok(u64::from_le_bytes(h[8..16].try_into().unwrap()));
        }
        Ok(ino.size)
    }

    /// Resolves a symlink's target relative to the link's own path (APFS absolute targets are volume-relative).
    fn link_target(&self, ino: &Inode, path: &str) -> io::Result<String> {
        let target = self.vol.readlink(ino)?;
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

    fn fill_info(&self, ino: &Inode, path: &str, out: &mut FileInfo) -> io::Result<()> {
        let mut attrs = if ino.is_dir() { FILE_ATTRIBUTE_DIRECTORY } else { FILE_ATTRIBUTE_READONLY };
        if path.rsplit('/').next().is_some_and(|n| n.starts_with('.') && n != "." && n != "..") {
            attrs |= FILE_ATTRIBUTE_HIDDEN;
        }
        out.reparse_tag = 0;
        if ino.is_symlink() {
            attrs |= FILE_ATTRIBUTE_REPARSE_POINT;
            out.reparse_tag = IO_REPARSE_TAG_SYMLINK;
            // Windows needs to know up front whether a link points at a directory.
            let target = self.link_target(ino, path).and_then(|t| self.vol.lookup(&t));
            if target.is_ok_and(|t| t.is_dir()) {
                attrs = (attrs & !FILE_ATTRIBUTE_READONLY) | FILE_ATTRIBUTE_DIRECTORY;
            }
        }
        let size = self.size_of(ino)?;
        out.file_attributes = attrs;
        out.file_size = size;
        out.allocation_size = size.div_ceil(self.c.block_size) * self.c.block_size;
        out.creation_time = filetime(ino.create_time);
        out.last_access_time = filetime(ino.access_time);
        out.last_write_time = filetime(ino.mod_time);
        out.change_time = filetime(ino.change_time);
        out.index_number = ino.id;
        out.hard_links = 0; // winfsp-rs: unimplemented, must be 0
        out.ea_size = 0;
        Ok(())
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
    fn reparse_data(&self, ino: &Inode, path: &str, buf: &mut [u8]) -> winfsp::Result<u64> {
        if !ino.is_symlink() {
            return Err(nt(STATUS_NOT_A_REPARSE_POINT));
        }
        let target = self.vol.readlink(ino).map_err(fsp)?;
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

fn filetime(ns: u64) -> u64 {
    ns / 100 + FILETIME_UNIX_EPOCH
}

fn parent(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(p, _)| p)
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
        let ino = self.vol.lookup(&path).map_err(fsp)?;
        let mut info = FileInfo::default();
        self.fill_info(&ino, &path, &mut info).map_err(fsp)?;
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
        let path = to_path(file_name);
        let ino = self.vol.lookup(&path).map_err(fsp)?;
        // shortcut: no normalized (on-disk case) name is reported for case-insensitive opens; add it if a
        // program depends on GetFinalPathNameByHandle returning the stored case.
        self.fill_info(&ino, &path, file_info.as_mut()).map_err(fsp)?;
        Ok(Handle { ino, path, file: OnceLock::new(), dir: DirBuffer::new() })
    }

    fn close(&self, _context: Handle) {}

    #[allow(clippy::too_many_arguments)]
    fn create(
        &self,
        _file_name: &U16CStr,
        _create_options: u32,
        _granted_access: u32,
        _file_attributes: u32,
        _security_descriptor: Option<&[c_void]>,
        _allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        _extra_buffer_is_reparse_point: bool,
        _file_info: &mut OpenFileInfo,
    ) -> winfsp::Result<Handle> {
        Err(nt(STATUS_MEDIA_WRITE_PROTECTED))
    }

    fn overwrite(&self, _: &Handle, _: u32, _: bool, _: u64, _: Option<&[u8]>, _: &mut FileInfo) -> winfsp::Result<()> {
        Err(nt(STATUS_MEDIA_WRITE_PROTECTED))
    }

    fn rename(&self, _: &Handle, _: &U16CStr, _: &U16CStr, _: bool) -> winfsp::Result<()> {
        Err(nt(STATUS_MEDIA_WRITE_PROTECTED))
    }

    #[allow(clippy::too_many_arguments)]
    fn set_basic_info(
        &self,
        _: &Handle,
        _: u32,
        _: u64,
        _: u64,
        _: u64,
        _: u64,
        _: &mut FileInfo,
    ) -> winfsp::Result<()> {
        Err(nt(STATUS_MEDIA_WRITE_PROTECTED))
    }

    fn set_delete(&self, _: &Handle, _: &U16CStr, _: bool) -> winfsp::Result<()> {
        Err(nt(STATUS_MEDIA_WRITE_PROTECTED))
    }

    fn set_file_size(&self, _: &Handle, _: u64, _: bool, _: &mut FileInfo) -> winfsp::Result<()> {
        Err(nt(STATUS_MEDIA_WRITE_PROTECTED))
    }

    fn write(&self, _: &Handle, _: &[u8], _: u64, _: bool, _: bool, _: &mut FileInfo) -> winfsp::Result<u32> {
        Err(nt(STATUS_MEDIA_WRITE_PROTECTED))
    }

    fn set_volume_label(&self, _: &U16CStr, _: &mut VolumeInfo) -> winfsp::Result<()> {
        Err(nt(STATUS_MEDIA_WRITE_PROTECTED))
    }

    fn get_file_info(&self, context: &Handle, file_info: &mut FileInfo) -> winfsp::Result<()> {
        self.fill_info(&context.ino, &context.path, file_info).map_err(fsp)
    }

    fn get_security(&self, _context: &Handle, security_descriptor: Option<&mut [c_void]>) -> winfsp::Result<u64> {
        Ok(self.copy_sd(security_descriptor))
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
            let mut di: DirInfo = DirInfo::new();
            if context.path != "/" {
                let up = self.vol.inode(context.ino.parent_id).map_err(fsp)?;
                for (name, ino, path) in
                    [(".", &context.ino, context.path.as_str()), ("..", &up, parent(&context.path))]
                {
                    di.reset();
                    self.fill_info(ino, path, di.file_info_mut()).map_err(fsp)?;
                    di.set_name(name)?;
                    lock.write(&mut di)?;
                }
            }
            for e in self.vol.read_dir(context.ino.id).map_err(fsp)? {
                let ino = self.vol.inode(e.id).map_err(fsp)?;
                di.reset();
                self.fill_info(&ino, &join(&context.path, &e.name), di.file_info_mut()).map_err(fsp)?;
                di.set_name(&e.name)?;
                lock.write(&mut di)?;
            }
        }
        Ok(context.dir.read(marker, buffer))
    }

    fn read(&self, context: &Handle, buffer: &mut [u8], offset: u64) -> winfsp::Result<u32> {
        let file = context.file.get_or_init(|| self.vol.open(&context.ino).map_err(|e| e.kind()));
        let file = file.as_ref().map_err(|&k| fsp(k.into()))?;
        if offset >= file.size {
            return Err(nt(STATUS_END_OF_FILE));
        }
        Ok(file.read_at(offset, buffer).map_err(fsp)? as u32)
    }

    fn get_volume_info(&self, out: &mut VolumeInfo) -> winfsp::Result<()> {
        let blocks = u64::from_le_bytes(self.c.superblock[40..48].try_into().unwrap()); // nx_block_count
        out.total_size = blocks * self.c.block_size;
        out.free_size = 0; // shortcut: free space isn't read from the space manager; fine while mounts are read-only
        out.set_volume_label(&self.vol.name);
        Ok(())
    }

    fn get_reparse_point_by_name(
        &self,
        file_name: &U16CStr,
        _is_directory: bool,
        buffer: &mut [u8],
    ) -> winfsp::Result<u64> {
        let path = to_path(file_name);
        let ino = self.vol.lookup(&path).map_err(fsp)?;
        self.reparse_data(&ino, &path, buffer)
    }

    fn get_reparse_point(&self, context: &Handle, _file_name: &U16CStr, buffer: &mut [u8]) -> winfsp::Result<u64> {
        self.reparse_data(&context.ino, &context.path, buffer)
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

/// Mounts `vol` at `mountpoint` (a drive like `X:` or a folder path that doesn't exist yet) until Ctrl+C.
pub fn mount(c: &'static Container, vol: Volume<'static>, mountpoint: &str) -> io::Result<()> {
    vol.root()?; // fail early on volumes we can't read (e.g. encrypted)
    preload_winfsp();
    winfsp::winfsp_init().map_err(|e| io::Error::other(format!("WinFsp is not installed or failed to load: {e:?}")))?;

    let block_size = c.block_size;
    let mut params = VolumeParams::new();
    params
        .filesystem_name("APFS")
        .sector_size(512)
        .sectors_per_allocation_unit((block_size / 512) as u16)
        .max_component_length(255)
        .volume_serial_number(u32::from_le_bytes(vol.superblock[240..244].try_into().unwrap()))
        .case_sensitive_search(!vol.case_insensitive())
        .case_preserved_names(true)
        .unicode_on_disk(true)
        .persistent_acls(true)
        .reparse_points(true)
        .read_only_volume(true)
        .post_cleanup_when_modified_only(true)
        .file_info_timeout(u32::MAX); // read-only data never changes under us, so let Windows cache it
    let fs = ApfsFs { c, vol, sd: security_descriptor()? };
    let mut host: FileSystemHost<ApfsFs> =
        FileSystemHost::new(params, fs).map_err(failed("creating the file system"))?;
    host.mount(mountpoint).map_err(failed("mounting"))?;
    host.start().map_err(failed("starting the dispatcher"))?;
    // SAFETY: registers a plain function; it only touches an atomic.
    unsafe { SetConsoleCtrlHandler(Some(on_ctrl), 1) };
    println!("mounted at {mountpoint} (read-only); press Ctrl+C to unmount");
    while !STOP.load(Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    host.stop();
    host.unmount();
    println!("unmounted");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symlinks_become_relative_reparse_points() {
        let img = concat!(env!("CARGO_MANIFEST_DIR"), "/ignored/testdata/case_insensitive.bin");
        let c: &'static Container = Box::leak(Box::new(Container::open(img).unwrap()));
        let fs = ApfsFs { c, vol: c.volumes().unwrap().remove(0), sd: vec![] };

        let link = fs.vol.lookup("/symlink-dir").unwrap();
        assert_eq!(fs.link_target(&link, "/symlink-dir").unwrap(), "dir");

        let link = fs.vol.lookup("/symlink-file").unwrap();
        let mut buf = [0u8; 256];
        let n = fs.reparse_data(&link, "/symlink-file", &mut buf).unwrap() as usize;
        let name: Vec<u16> = "dir\\file".encode_utf16().collect();
        assert_eq!(n, 20 + 4 * name.len());
        assert_eq!(u32::from_le_bytes(buf[0..4].try_into().unwrap()), IO_REPARSE_TAG_SYMLINK);
        assert_eq!(u16::from_le_bytes(buf[4..6].try_into().unwrap()) as usize, n - 8);
        assert_eq!(u32::from_le_bytes(buf[16..20].try_into().unwrap()), SYMLINK_FLAG_RELATIVE);
        let sub: Vec<u16> = buf[20..20 + 2 * name.len()].chunks(2).map(|b| u16::from_le_bytes([b[0], b[1]])).collect();
        assert_eq!(sub, name);

        let file = fs.vol.lookup("/dir/file").unwrap();
        assert!(fs.reparse_data(&file, "/dir/file", &mut buf).is_err());
    }
}
