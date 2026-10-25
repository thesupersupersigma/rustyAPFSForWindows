//! Regression tests from a review of the write engine: each failed before its fix.

use rusty_apfs::Container;
use rusty_apfs::write::{Kind, Writer};
use std::path::{Path, PathBuf};
use std::process::Command;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn tool(name: &str) -> PathBuf {
    root().join("tools/bin").join(format!("{name}.exe"))
}

fn temp(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("rusty-apfs-review-{}-{name}", std::process::id()))
}

fn fresh(name: &str, mib: u64) -> PathBuf {
    let p = temp(&format!("{name}.img"));
    std::fs::File::create(&p).unwrap().set_len(mib << 20).unwrap();
    let out = Command::new(tool("mkapfs")).arg(&p).output().unwrap();
    assert!(out.status.success(), "mkapfs failed: {}", String::from_utf8_lossy(&out.stderr));
    p
}

fn copy_of(image: &str) -> PathBuf {
    let src = root().join("ignored/testdata").join(format!("{image}.bin"));
    let dst = temp(&format!("{image}.img"));
    std::fs::copy(&src, &dst).unwrap();
    dst
}

fn fsck_text(p: &Path) -> String {
    let out = Command::new(tool("apfsck")).arg("-cw").arg(p).output().unwrap();
    format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr))
}

fn fsck(p: &Path) {
    let t = fsck_text(p);
    assert!(t.trim().is_empty(), "apfsck on {}:\n{t}", p.display());
}

fn read(p: &Path, path: &str) -> Vec<u8> {
    let c = Container::open(p).unwrap();
    let v = c.volumes().unwrap().remove(0);
    v.open(&v.lookup(path).unwrap()).unwrap().read_all().unwrap()
}

/// Makes `files` originals of `blocks` blocks, clones each and rewrites every other block of the
/// clones, so removing the originals frees `files * blocks / 2` separate one-block ranges.
fn fragmented_originals(w: &mut Writer, files: usize, blocks: u64) {
    let bs = w.block_size();
    let mut clones = vec![];
    for k in 0..files {
        let f = w.create(0, 2, &format!("orig{k}"), Kind::File, 0o644).unwrap();
        w.write_at(0, f, 0, &vec![0x11; (blocks * bs) as usize]).unwrap();
        clones.push(w.clone_file(0, f, 2, &format!("clone{k}")).unwrap());
        if k % 20 == 19 {
            w.commit().unwrap();
        }
    }
    w.commit().unwrap();
    for (k, &c) in clones.iter().enumerate() {
        for i in (0..blocks).step_by(2) {
            w.write_at(0, c, i * bs, &vec![0x22; bs as usize]).unwrap();
        }
        if k % 10 == 9 {
            w.commit().unwrap();
        }
    }
    w.commit().unwrap();
}

/// One operation that frees more separate ranges than the main free queue can describe makes every
/// later commit fail; the rollback then also throws away unrelated, already-acknowledged changes.
#[test]
fn review_fragmented_delete_can_be_committed() {
    let p = fresh("fq-small", 64);
    let mut w = Writer::open(&p, None).unwrap();
    fragmented_originals(&mut w, 5, 200); // 500 separate ranges; a 64 MiB container's queue holds 426
    let keep = w.create(0, 2, "keep.txt", Kind::File, 0o644).unwrap();
    w.write_at(0, keep, 0, b"precious").unwrap();
    for k in 0..5 {
        w.remove(0, 2, &format!("orig{k}")).unwrap();
    }
    let r = w.commit();
    drop(w);
    assert!(r.is_ok(), "commit failed: {r:?}");
    assert_eq!(read(&p, "keep.txt"), b"precious");
    fsck(&p);
}

/// On containers over ~1.25 GiB the main free queue may need more than 142 leaves, but its root
/// can only index 142: `tree::serialize` then writes overlapping keys and values.
#[test]
#[ignore] // needs ~1.5 GB of temp space and a minute
fn review_large_free_queue_root_fits() {
    let p = fresh("fq-big", 1536); // node limit 174
    let mut w = Writer::open(&p, None).unwrap();
    fragmented_originals(&mut w, 300, 140); // 21000 separate ranges -> 148 leaves
    for k in 0..300 {
        w.remove(0, 2, &format!("orig{k}")).unwrap();
    }
    w.commit().unwrap();
    drop(w);
    let reopened = Writer::open(&p, None);
    assert!(reopened.is_ok(), "reopen failed: {:?}", reopened.err());
    drop(reopened);
    fsck(&p);
    std::fs::remove_file(&p).unwrap();
}

/// `rename` validates "directory into itself" only after removing the replaced target, so the
/// failure rolls back every uncommitted change, not just its own.
#[test]
fn review_failed_rename_keeps_other_changes() {
    let p = fresh("rename", 64);
    let mut w = Writer::open(&p, None).unwrap();
    let a = w.create(0, 2, "a", Kind::Dir, 0o755).unwrap();
    let b = w.create(0, a, "b", Kind::Dir, 0o755).unwrap();
    w.create(0, b, "x", Kind::Dir, 0o755).unwrap();
    w.commit().unwrap();
    let keep = w.create(0, 2, "keep.txt", Kind::File, 0o644).unwrap();
    w.write_at(0, keep, 0, b"precious").unwrap();
    assert!(w.rename(0, 2, "a", b, "x", true).is_err());
    // The failed rename must leave the target in place and the writer usable.
    assert!(w.view(0).unwrap().lookup("a/b/x").is_ok(), "failed rename half-applied (target removed)");
    let r = w.commit();
    assert!(r.is_ok(), "writer unusable after a failed operation: {r:?}");
    assert!(w.view(0).unwrap().lookup("keep.txt").is_ok(), "an unrelated, successful change was rolled back");
}

/// `rollback` reopens the image with `Writer::open`, which the exclusive-writer lock refuses while
/// this writer still holds the device, so every rollback poisons the writer.
#[test]
fn review_rollback_reopens() {
    let p = fresh("rollback", 64);
    let mut w = Writer::open(&p, None).unwrap();
    let a = w.create(0, 2, "a", Kind::Dir, 0o755).unwrap();
    let b = w.create(0, a, "b", Kind::Dir, 0o755).unwrap();
    w.create(0, b, "x", Kind::Dir, 0o755).unwrap();
    w.commit().unwrap();
    let e = w.rename(0, 2, "a", b, "x", true).unwrap_err(); // fails after removing a/b/x
    let after = w.create(0, 2, "after.txt", Kind::File, 0o644);
    assert!(after.is_ok(), "rename error {e}; next operation: {:?}", after.err());
}

/// Writing to a compressed file decompresses it; the new data stream must get its dstream-id record.
#[test]
fn review_write_to_compressed_file() {
    let p = copy_of("case_insensitive");
    let before = fsck_text(&p);
    let mut w = Writer::open(&p, None).unwrap();
    let ino = w.view(0).unwrap().lookup("dir/compressed-zlib-xattr").unwrap().id;
    w.write_at(0, ino, 0, b"X").unwrap();
    w.commit().unwrap();
    drop(w);
    let after = fsck_text(&p);
    assert_eq!(before, after, "apfsck output changed after writing to a compressed file");
}

/// `rename` and `link` never check that the new parent is a directory: the entry lands under a
/// regular file and that file's link count is bumped as if it were a directory's child count.
#[test]
fn review_rename_into_a_file_is_refused() {
    let p = fresh("rename-file-parent", 64);
    let mut w = Writer::open(&p, None).unwrap();
    let f = w.create(0, 2, "file.txt", Kind::File, 0o644).unwrap();
    w.create(0, 2, "moved.txt", Kind::File, 0o644).unwrap();
    w.commit().unwrap();
    let r = w.rename(0, 2, "moved.txt", f, "child", false);
    if r.is_ok() {
        w.commit().unwrap();
        drop(w);
        panic!("rename under a regular file succeeded; apfsck:\n{}", fsck_text(&p));
    }
}

#[test]
fn review_link_into_a_file_is_refused() {
    let p = fresh("link-file-parent", 64);
    let mut w = Writer::open(&p, None).unwrap();
    let f = w.create(0, 2, "file.txt", Kind::File, 0o644).unwrap();
    let g = w.create(0, 2, "other.txt", Kind::File, 0o644).unwrap();
    w.commit().unwrap();
    let r = w.link(0, g, f, "child");
    if r.is_ok() {
        w.commit().unwrap();
        drop(w);
        panic!("link under a regular file succeeded; apfsck:\n{}", fsck_text(&p));
    }
}

/// Extent lengths have 56 bits; a write (or set_size) far past the end makes a hole longer than that,
/// and the excess lands in the extent's flag bits.
#[test]
fn review_huge_offset_is_refused_or_clean() {
    let p = fresh("huge-offset", 64);
    let mut w = Writer::open(&p, None).unwrap();
    let f = w.create(0, 2, "sparse.bin", Kind::File, 0o644).unwrap();
    let r = w.write_at(0, f, 1 << 57, b"x");
    if r.is_ok() {
        w.commit().unwrap();
        drop(w);
        fsck(&p);
    }
}
