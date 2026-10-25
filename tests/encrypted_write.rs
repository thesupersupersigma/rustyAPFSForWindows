//! Writes to software-encrypted volumes, checked by reopening with our reader (apfsck can't check
//! software encryption).

use rusty_apfs::Container;
use rusty_apfs::write::{Kind, Writer};
use std::io::ErrorKind;
use std::path::PathBuf;

fn copy_of(image: &str) -> PathBuf {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("ignored/testdata").join(format!("{image}.bin"));
    assert!(src.exists(), "missing {}: run `python scripts/fetch-testdata.py`", src.display());
    let dst = std::env::temp_dir().join(format!("rusty-apfs-{}-enc-{image}.img", std::process::id()));
    std::fs::copy(&src, &dst).unwrap();
    dst
}

fn pattern(n: usize, seed: u8) -> Vec<u8> {
    (0..n).map(|i| (i as u32).wrapping_mul(2654435761).rotate_left(seed as u32 % 31) as u8 ^ seed).collect()
}

fn read(p: &PathBuf, path: &str) -> Vec<u8> {
    let c = Container::open(p).unwrap();
    let mut v = c.volumes().unwrap().remove(0);
    v.unlock("password").unwrap();
    v.open(&v.lookup(path).unwrap()).unwrap().read_all().unwrap()
}

fn exercise(image: &str) {
    let p = copy_of(image);
    let original = read(&p, "dir/file");
    let mut w = Writer::open(&p, None).unwrap();
    assert!(w.is_locked(0));
    assert_eq!(w.create(0, 2, "x", Kind::File, 0o644).unwrap_err().kind(), ErrorKind::ReadOnlyFilesystem);
    assert_eq!(w.unlock(0, "wrong").unwrap_err().kind(), ErrorKind::PermissionDenied);
    w.unlock(0, "password").unwrap();
    assert!(w.read_only_reason(0).is_none());

    let d = w.create(0, 2, "From Windows", Kind::Dir, 0o755).unwrap();
    let f = w.create(0, d, "secret.bin", Kind::File, 0o644).unwrap();
    let mut model = pattern(300_000, 7);
    w.write_at(0, f, 0, &model).unwrap();
    w.commit().unwrap();
    // Overwrite in place across blocks, shrink, grow with a hole, write past it.
    let patch = pattern(9_000, 3);
    w.write_at(0, f, 5_000, &patch).unwrap();
    model[5_000..14_000].copy_from_slice(&patch);
    w.set_size(0, f, 100_001).unwrap();
    model.truncate(100_001);
    w.write_at(0, f, 150_000, b"tail").unwrap();
    model.resize(150_000, 0);
    model.extend(b"tail");
    // Clone and hard link; then edit the clone (copy-on-write of encrypted blocks).
    let c = w.clone_file(0, f, 2, "clone.bin").unwrap();
    w.link(0, f, 2, "link.bin").unwrap();
    w.write_at(0, c, 0, b"CLONE").unwrap();
    let mut clone = model.clone();
    clone[..5].copy_from_slice(b"CLONE");
    // Edit an Apple-written file in place, rename and delete existing entries.
    let existing = w.view(0).unwrap().lookup("dir/file").unwrap().id;
    w.write_at(0, existing, 0, b"EDIT").unwrap();
    let mut edited = original.clone();
    edited[..4].copy_from_slice(b"EDIT");
    w.rename(0, 2, "empty", d, "moved-empty", false).unwrap();
    w.remove(0, 2, "symlink-dir").unwrap();
    w.commit().unwrap();
    drop(w);

    assert_eq!(read(&p, "From Windows/secret.bin"), model);
    assert_eq!(read(&p, "link.bin"), model);
    assert_eq!(read(&p, "clone.bin"), clone);
    assert_eq!(read(&p, "dir/file"), edited);
    assert_eq!(read(&p, "From Windows/moved-empty"), b"");
    // Untouched Apple-written data still reads, including compressed files.
    assert_eq!(read(&p, "dir/compressed-zlib-xattr").len(), 116);
    let c = Container::open(&p).unwrap();
    let mut v = c.volumes().unwrap().remove(0);
    v.unlock("password").unwrap();
    assert!(v.lookup("symlink-dir").is_err());
    drop(c);

    // Reopen the writer (fresh unlock) and keep going.
    let mut w = Writer::open(&p, None).unwrap();
    w.unlock(0, "password").unwrap();
    w.remove(0, d, "secret.bin").unwrap();
    w.remove(0, 2, "clone.bin").unwrap();
    w.commit().unwrap();
    drop(w);
    assert_eq!(read(&p, "link.bin"), model);
    // Nothing we wrote may appear in the clear: names live in encrypted tree nodes, data in encrypted blocks.
    let raw = std::fs::read(&p).unwrap();
    let found = |needle: &[u8]| raw.windows(needle.len()).any(|w| w == needle);
    assert!(!found(b"From Windows"), "file name stored in plaintext");
    assert!(!found(b"moved-empty"), "file name stored in plaintext");
    assert!(!found(&model[20_000..20_064]), "file data stored in plaintext");
    assert!(!found(b"EDIT"), "overwritten data stored in plaintext");
    std::fs::remove_file(&p).unwrap();
}

#[test]
fn write_encrypted_volume() {
    exercise("encrypted");
}

#[test]
fn write_converted_encrypted_volume() {
    // 128-bit key and crypto ids that differ from physical addresses.
    exercise("jhfs_encrypted");
}
