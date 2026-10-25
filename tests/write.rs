//! Write tests: change an image through `Writer`, commit, then check it with our reader and with apfsck
//! (built by `python scripts/build-apfsprogs.py`). Images are copies in the temp dir.

use rusty_apfs::Container;
use rusty_apfs::write::{Kind, Writer};
use std::path::{Path, PathBuf};
use std::process::Command;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn tool(name: &str) -> PathBuf {
    let p = root().join("tools/bin").join(format!("{name}.exe"));
    assert!(p.exists(), "missing {}: run `python scripts/build-apfsprogs.py`", p.display());
    p
}

fn temp(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("rusty-apfs-{}-{name}", std::process::id()))
}

/// A copy of one of the dissect test images.
fn copy_of(image: &str) -> PathBuf {
    let src = root().join("ignored/testdata").join(format!("{image}.bin"));
    assert!(src.exists(), "missing {}: run `python scripts/fetch-testdata.py`", src.display());
    let dst = temp(&format!("{image}.img"));
    std::fs::copy(&src, &dst).unwrap();
    dst
}

/// A freshly formatted image from mkapfs.
fn fresh(name: &str, mib: u64, args: &[&str]) -> PathBuf {
    let p = temp(&format!("{name}.img"));
    std::fs::File::create(&p).unwrap().set_len(mib << 20).unwrap();
    let out = Command::new(tool("mkapfs")).args(args).arg(&p).output().unwrap();
    assert!(out.status.success(), "mkapfs failed: {}", String::from_utf8_lossy(&out.stderr));
    p
}

/// Runs apfsck; panics with its output if it finds a problem.
fn fsck(p: &Path) {
    let out = Command::new(tool("apfsck")).arg("-cw").arg(p).output().unwrap();
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success() && text.trim().is_empty(), "apfsck on {}:\n{text}", p.display());
}

fn read(p: &Path, path: &str) -> Vec<u8> {
    let c = Container::open(p).unwrap();
    let v = c.volumes().unwrap().remove(0);
    v.open(&v.lookup(path).unwrap()).unwrap().read_all().unwrap()
}

#[test]
fn fresh_image_is_clean() {
    let p = fresh("clean", 64, &["-L", "Fresh"]);
    fsck(&p);
}

#[test]
fn create_empty_file() {
    let p = fresh("empty-file", 64, &["-L", "Fresh"]);
    let mut w = Writer::open(&p, None).unwrap();
    w.create(0, 2, "hello.txt", Kind::File, 0o644).unwrap();
    w.commit().unwrap();
    drop(w);
    assert_eq!(read(&p, "hello.txt"), b"");
    fsck(&p);
}

fn pattern(n: usize, seed: u8) -> Vec<u8> {
    (0..n).map(|i| (i as u32).wrapping_mul(2654435761).rotate_left(seed as u32 % 31) as u8 ^ seed).collect()
}

#[test]
fn file_data_round_trips() {
    let p = fresh("data", 64, &["-L", "Data"]);
    let mut w = Writer::open(&p, None).unwrap();
    let small = w.create(0, 2, "small.txt", Kind::File, 0o644).unwrap();
    w.write_at(0, small, 0, b"hello from windows\n").unwrap();
    let big = w.create(0, 2, "big.bin", Kind::File, 0o644).unwrap();
    let data = pattern(3 * 1024 * 1024 + 123, 7);
    for (i, chunk) in data.chunks(65536).enumerate() {
        w.write_at(0, big, (i * 65536) as u64, chunk).unwrap();
    }
    w.commit().unwrap();
    drop(w);
    assert_eq!(read(&p, "small.txt"), b"hello from windows\n");
    assert_eq!(read(&p, "big.bin"), data);
    fsck(&p);
}

#[test]
fn overwrite_truncate_and_sparse() {
    let p = fresh("edit", 64, &["-L", "Edit"]);
    let mut w = Writer::open(&p, None).unwrap();
    let f = w.create(0, 2, "f", Kind::File, 0o644).unwrap();
    let mut model = pattern(100_000, 3);
    w.write_at(0, f, 0, &model).unwrap();
    w.commit().unwrap();
    // Overwrite across block boundaries, in place.
    let patch = pattern(10_000, 9);
    w.write_at(0, f, 4000, &patch).unwrap();
    model[4000..14000].copy_from_slice(&patch);
    // Shrink to a non-block size, then grow with a hole, then write past the hole.
    w.set_size(0, f, 50_001).unwrap();
    model.truncate(50_001);
    w.set_size(0, f, 200_000).unwrap();
    model.resize(200_000, 0);
    w.write_at(0, f, 300_000, b"tail").unwrap();
    model.resize(300_000, 0);
    model.extend(b"tail");
    w.commit().unwrap();
    drop(w);
    assert_eq!(read(&p, "f"), model);
    fsck(&p);
}

#[test]
fn directories_rename_delete() {
    let p = fresh("dirs", 64, &["-L", "Dirs"]);
    let mut w = Writer::open(&p, None).unwrap();
    let a = w.create(0, 2, "a", Kind::Dir, 0o755).unwrap();
    let b = w.create(0, a, "b", Kind::Dir, 0o755).unwrap();
    let f = w.create(0, b, "file.txt", Kind::File, 0o644).unwrap();
    w.write_at(0, f, 0, b"nested").unwrap();
    w.create(0, 2, "link", Kind::Symlink("a/b/file.txt".into()), 0).unwrap();
    let gone = w.create(0, 2, "gone.txt", Kind::File, 0o644).unwrap();
    w.write_at(0, gone, 0, &pattern(20_000, 1)).unwrap();
    w.commit().unwrap();
    w.rename(0, b, "file.txt", 2, "moved.txt", false).unwrap();
    w.rename(0, 2, "a", 2, "A renamed", false).unwrap();
    w.remove(0, 2, "gone.txt").unwrap();
    assert!(w.remove(0, a, "b").is_ok());
    assert_eq!(w.remove(0, 2, "missing").unwrap_err().kind(), std::io::ErrorKind::NotFound);
    w.commit().unwrap();
    drop(w);
    assert_eq!(read(&p, "moved.txt"), b"nested");
    let c = Container::open(&p).unwrap();
    let v = c.volumes().unwrap().remove(0);
    let mut names: Vec<String> = v.read_dir(2).unwrap().into_iter().map(|e| e.name).collect();
    names.sort();
    assert_eq!(names, ["A renamed", "link", "moved.txt"]);
    assert_eq!(v.readlink(&v.lookup("link").unwrap()).unwrap(), "a/b/file.txt");
    // Case-insensitive volume: lookups ignore case.
    assert!(v.lookup("MOVED.TXT").is_ok());
    drop(c);
    fsck(&p);
}

#[test]
fn many_files_split_the_tree() {
    let p = fresh("many", 64, &["-L", "Many"]);
    let mut w = Writer::open(&p, None).unwrap();
    let d = w.create(0, 2, "many", Kind::Dir, 0o755).unwrap();
    for i in 0..1500 {
        let f = w.create(0, d, &format!("file number {i:05} with a longish name.txt"), Kind::File, 0o644).unwrap();
        if i % 3 == 0 {
            w.write_at(0, f, 0, format!("contents of {i}").as_bytes()).unwrap();
        }
        if i % 250 == 0 {
            w.commit().unwrap();
        }
    }
    w.commit().unwrap();
    for i in (0..1500).step_by(2) {
        w.remove(0, d, &format!("file number {i:05} with a longish name.txt")).unwrap();
    }
    w.commit().unwrap();
    drop(w);
    let c = Container::open(&p).unwrap();
    let v = c.volumes().unwrap().remove(0);
    assert_eq!(v.read_dir(d).unwrap().len(), 750);
    let f = v.lookup("many/file number 00003 with a longish name.txt").unwrap();
    assert_eq!(v.open(&f).unwrap().read_all().unwrap(), b"contents of 3");
    drop(c);
    fsck(&p);
}

#[test]
fn many_commits() {
    let p = fresh("commits", 64, &["-L", "Commits"]);
    let mut w = Writer::open(&p, None).unwrap();
    let f = w.create(0, 2, "log.txt", Kind::File, 0o644).unwrap();
    let mut model = vec![];
    for i in 0..60 {
        let line = format!("line {i}\n");
        w.write_at(0, f, model.len() as u64, line.as_bytes()).unwrap();
        model.extend(line.as_bytes());
        w.commit().unwrap();
    }
    drop(w);
    // Reopen and keep going: the writer must pick up its own checkpoints.
    let mut w = Writer::open(&p, None).unwrap();
    w.write_at(0, f, model.len() as u64, b"after reopen\n").unwrap();
    model.extend(b"after reopen\n");
    w.commit().unwrap();
    drop(w);
    assert_eq!(read(&p, "log.txt"), model);
    fsck(&p);
}

#[test]
fn writes_to_an_apple_made_volume() {
    let p = copy_of("large");
    let mut w = Writer::open(&p, None).unwrap();
    let ino = w.view(0).unwrap().lookup("yomomma.bin").unwrap().id;
    w.write_at(0, ino, 1000, b"edited on windows").unwrap();
    let d = w.create(0, 2, "From Windows", Kind::Dir, 0o755).unwrap();
    let f = w.create(0, d, "notes.txt", Kind::File, 0o644).unwrap();
    w.write_at(0, f, 0, &pattern(70_000, 5)).unwrap();
    w.commit().unwrap();
    drop(w);
    let got = read(&p, "yomomma.bin");
    assert_eq!(got.len(), 512 << 20);
    assert_eq!(&got[1000..1017], b"edited on windows");
    assert!(got[..1000].iter().chain(&got[1017..2_000_000]).all(|&b| b == 0x67));
    assert_eq!(read(&p, "From Windows/notes.txt"), pattern(70_000, 5));
    fsck(&p);
    std::fs::remove_file(&p).unwrap();
}

/// Containers over ~3 TB keep chunk-info addresses in CABs. Needs a big sparse image made by hand:
/// set RUSTY_APFS_BIG_IMAGE to an mkapfs-formatted sparse file (e.g. 4 TiB).
#[test]
#[ignore]
fn big_container_with_cabs() {
    let p = PathBuf::from(std::env::var("RUSTY_APFS_BIG_IMAGE").expect("set RUSTY_APFS_BIG_IMAGE"));
    let mut w = Writer::open(&p, None).unwrap();
    let f = w.create(0, 2, "big.bin", Kind::File, 0o644).unwrap();
    let data = pattern(5 << 20, 4);
    w.write_at(0, f, 0, &data).unwrap();
    w.commit().unwrap();
    w.set_size(0, f, 1 << 20).unwrap();
    w.commit().unwrap();
    drop(w);
    assert_eq!(read(&p, "big.bin"), &data[..1 << 20]);
    fsck(&p);
}

#[test]
fn hard_links() {
    let p = fresh("links", 64, &["-L", "Links"]);
    let mut w = Writer::open(&p, None).unwrap();
    let d = w.create(0, 2, "d", Kind::Dir, 0o755).unwrap();
    let f = w.create(0, 2, "orig.txt", Kind::File, 0o644).unwrap();
    w.write_at(0, f, 0, b"shared contents").unwrap();
    w.link(0, f, d, "link1.txt").unwrap();
    w.link(0, f, 2, "link2.txt").unwrap();
    w.commit().unwrap();
    fsck(&p);
    assert_eq!(read(&p, "d/link1.txt"), b"shared contents");
    // Writes through one name show through the others.
    w.write_at(0, f, 0, b"SHARED").unwrap();
    // Remove the primary link, rename another.
    w.remove(0, 2, "orig.txt").unwrap();
    w.rename(0, d, "link1.txt", 2, "renamed.txt", false).unwrap();
    w.commit().unwrap();
    drop(w);
    fsck(&p);
    assert_eq!(read(&p, "renamed.txt"), b"SHARED contents");
    assert_eq!(read(&p, "link2.txt"), b"SHARED contents");
    let mut w = Writer::open(&p, None).unwrap();
    w.remove(0, 2, "renamed.txt").unwrap();
    w.remove(0, 2, "link2.txt").unwrap();
    w.commit().unwrap();
    drop(w);
    fsck(&p);
}

#[test]
fn clones_share_until_written() {
    let p = fresh("clones", 64, &["-L", "Clones"]);
    let mut w = Writer::open(&p, None).unwrap();
    let f = w.create(0, 2, "orig.bin", Kind::File, 0o644).unwrap();
    let data = pattern(300_000, 2);
    w.write_at(0, f, 0, &data).unwrap();
    w.commit().unwrap();
    let free_before = w.free_blocks();
    let c = w.clone_file(0, f, 2, "copy.bin").unwrap();
    w.commit().unwrap();
    // Cloning costs metadata only.
    let used = free_before.saturating_sub(w.free_blocks());
    assert!(used < 40, "clone used {used} blocks"); // data is 74 blocks; a commit copies ~10 metadata blocks
    fsck(&p);
    // Write to the clone: copy-on-write, the original is untouched.
    w.write_at(0, c, 5000, b"clone edit").unwrap();
    w.commit().unwrap();
    fsck(&p);
    let mut edited = data.clone();
    edited[5000..5010].copy_from_slice(b"clone edit");
    assert_eq!(read(&p, "orig.bin"), data);
    assert_eq!(read(&p, "copy.bin"), edited);
    // Truncate the original, then delete it: the clone keeps its blocks.
    w.set_size(0, f, 1000).unwrap();
    w.commit().unwrap();
    fsck(&p);
    w.remove(0, 2, "orig.bin").unwrap();
    w.commit().unwrap();
    drop(w);
    fsck(&p);
    assert_eq!(read(&p, "copy.bin"), edited);
}
