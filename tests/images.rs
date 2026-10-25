//! End-to-end checks against real APFS images (fetch them with `python scripts/fetch-testdata.py`).
//! Expected values are facts about dissect.apfs's test images, recorded in their test suite.

use rusty_apfs::{Container, Volume};
use sha2::{Digest, Sha256};
use std::io::ErrorKind;
use std::path::PathBuf;

fn image(name: &str) -> Container {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("ignored/testdata").join(format!("{name}.bin"));
    assert!(p.exists(), "missing {}: run `python scripts/fetch-testdata.py`", p.display());
    Container::open(p).unwrap()
}

fn read(v: &Volume, path: &str) -> Vec<u8> {
    v.open(&v.lookup(path).unwrap()).unwrap().read_all().unwrap()
}

fn sha(b: &[u8]) -> String {
    Sha256::digest(b).iter().map(|x| format!("{x:02x}")).collect()
}

fn names(v: &Volume, path: &str) -> Vec<String> {
    v.read_dir(v.lookup(path).unwrap().id).unwrap().into_iter().map(|e| e.name).collect()
}

fn has_all(have: &[String], want: &[&str]) {
    for w in want {
        assert!(have.iter().any(|h| h == w), "missing {w:?} in {have:?}");
    }
}

const COMPRESSED: &str = "Compressed data in xattr aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n";
const COMPRESSED_FORK_SHA: &str = "5f46d97f947137dcf974fc19914c547acd18fcdb25124c846c1100f8b3fbca5f";

fn check_content(v: &Volume, beta: bool) {
    let root = names(v, "/");
    has_all(
        &root,
        &[
            ".fseventsd",
            "case_folding_\u{b5}",
            "dir",
            "empty",
            "hardlink",
            "nfd_te\u{301}stfile\u{300}",
            "nfd_\u{be}",
            "nfkd_3\u{2044}4",
            "symlink-dir",
            "symlink-file",
        ],
    );
    let jhfs = root.iter().any(|n| n == ".HFS+ Private Directory Data\r");

    assert!(v.lookup("dir").unwrap().is_dir());
    assert!(v.lookup("empty").unwrap().is_file());
    assert_eq!(read(v, "empty"), b"");
    match v.lookup("EMPTY") {
        Ok(i) => assert!(v.case_insensitive() && i.id == v.lookup("empty").unwrap().id),
        Err(e) => assert!(!v.case_insensitive() && e.kind() == ErrorKind::NotFound),
    }

    let mut want = vec![
        "compressed-zlib-fork",
        "compressed-zlib-xattr",
        "fifo",
        "file",
        "resourcefork",
        "xattr-dir",
        "xattr-large",
        "xattr-small",
    ];
    if !beta {
        want.extend([
            "compressed-lzfse-fork",
            "compressed-lzfse-xattr",
            "compressed-lzvn-fork",
            "compressed-lzvn-xattr",
        ]);
    }
    has_all(&names(v, "dir"), &want);

    assert_eq!(read(v, "dir/file"), "\u{f8ff} File System\n".as_bytes());
    let (file, link) = (v.lookup("dir/file").unwrap(), v.lookup("hardlink").unwrap());
    assert_eq!(file.id, link.id, "hard link shares the inode");

    for (path, target) in [("symlink-file", "dir/file"), ("symlink-dir", "dir")] {
        let ino = v.lookup(path).unwrap();
        assert!(ino.is_symlink());
        assert_eq!(v.readlink(&ino).unwrap(), target);
    }

    // Names are returned as stored, but lookups ignore Unicode normalization.
    if !jhfs {
        v.lookup("nfc_t\u{e9}stfil\u{e8}").unwrap();
    }
    v.lookup("nfd_t\u{e9}stfil\u{e8}").unwrap();
    v.lookup("nfd_\u{be}").unwrap();
    v.lookup("nfkd_3\u{2044}4").unwrap();
    v.lookup("case_folding_\u{b5}").unwrap();

    let xattr = |path: &str, name: &str| v.xattr(v.lookup(path).unwrap().id, name).unwrap().unwrap();
    assert_eq!(xattr("dir/resourcefork", "com.apple.ResourceFork"), b"Resource fork data\n");
    assert_eq!(xattr("dir/xattr-small", "xattr-small"), b"Small xattr data");
    assert_eq!(xattr("dir/xattr-dir", "xattr-dir"), b"xattr data on directory");
    let large_sha = if beta {
        "dd4e6730520932767ec0a9e33fe19c4ce24399d6eba4ff62f13013c9ed30ef87"
    } else {
        "a11c957142c3fd8ebf2bee1ed0cf184a246033a3874d060acd28c319b323466e"
    };
    assert_eq!(sha(&xattr("dir/xattr-large", "xattr-large")), large_sha);

    let algos: &[&str] = if beta { &["zlib"] } else { &["zlib", "lzvn", "lzfse"] };
    for algo in algos {
        let inline = v.lookup(&format!("dir/compressed-{algo}-xattr")).unwrap();
        assert!(inline.is_compressed());
        assert_eq!(v.open(&inline).unwrap().read_all().unwrap(), COMPRESSED.as_bytes(), "{algo} xattr");
        assert_eq!(sha(&read(v, &format!("dir/compressed-{algo}-fork"))), COMPRESSED_FORK_SHA, "{algo} fork");
    }

    if !jhfs && !beta {
        assert_eq!(v.lookup("dir/blockdev").unwrap().mode & 0o170000, 0o060000);
        let chardev = v.lookup("dir/chardev-linux").unwrap();
        assert_eq!(chardev.mode & 0o170000, 0o020000);
        assert!(chardev.rdev.is_some());
    }
    assert_eq!(v.lookup("dir/fifo").unwrap().mode & 0o170000, 0o010000);
}

fn single_volume<'c>(c: &'c Container, name: &str, incompat: u64) -> Volume<'c> {
    let mut vols = c.volumes().unwrap();
    assert_eq!(vols.len(), 1);
    let v = vols.remove(0);
    assert_eq!(v.name, name);
    assert_eq!(v.incompatible_features, incompat);
    v
}

#[test]
fn case_insensitive() {
    check_content(&single_volume(&image("case_insensitive"), "Case Insensitive", 0x1), false);
}

#[test]
fn case_sensitive() {
    check_content(&single_volume(&image("case_sensitive"), "Case Sensitive", 0x8), false);
}

#[test]
fn case_insensitive_beta() {
    check_content(&single_volume(&image("case_insensitive_beta"), "Case Insensitive (beta)", 0x1), true);
}

#[test]
fn case_sensitive_beta() {
    check_content(&single_volume(&image("case_sensitive_beta"), "Case Sensitive (beta)", 0x0), true);
}

#[test]
fn jhfs_converted() {
    check_content(&single_volume(&image("jhfs_converted"), "JHFS+ Converted", 0x1), false);
}

#[test]
fn encrypted_volumes_are_refused_cleanly() {
    let c = image("encrypted");
    let v = single_volume(&c, "Encrypted", 0x5);
    assert!(v.encrypted);
    assert_eq!(v.root().unwrap_err().kind(), ErrorKind::Unsupported);
}

#[test]
fn snapshots() {
    let c = image("snapshot");
    let v = single_volume(&c, "Snapshots", 0x1);
    assert!(!names(&v, "/").contains(&"file".to_string()));
    let snaps = v.snapshots().unwrap();
    assert_eq!(snaps.len(), 512);
    for (i, s) in snaps.iter().enumerate() {
        assert_eq!(s.name, format!("Snapshot {i}"));
        assert_eq!(read(&v.snapshot(s).unwrap(), "file"), format!("Snapshot {i}\n").as_bytes());
    }
}

#[test]
fn corrupt_checkpoints_fall_back() {
    let c = image("corrupt");
    assert_eq!(c.xid, 302);
    assert!(c.skipped[0].starts_with("Skipping superblock xid=304: invalid OMAP"), "{:?}", c.skipped);
    assert_eq!(c.skipped[1], "Skipping superblock xid=303: Invalid nx_superblock checksum");
    assert_eq!(c.volumes().unwrap().len(), 1);
}

#[test]
fn large_file_reads_only_what_is_asked() {
    let c = image("large");
    let v = single_volume(&c, "Large", 0x1);
    let ino = v.lookup("yomomma.bin").unwrap();
    assert_eq!(ino.size, 512 * 1024 * 1024);
    let f = v.open(&ino).unwrap();
    let mut buf = [0u8; 512];
    assert_eq!(f.read_at(0, &mut buf).unwrap(), 512);
    assert!(buf.iter().all(|&b| b == 0x67));
    // Reading across the end returns only the remaining bytes.
    assert_eq!(f.read_at(ino.size - 100, &mut buf).unwrap(), 100);
    assert_eq!(f.read_at(ino.size, &mut buf).unwrap(), 0);
}
