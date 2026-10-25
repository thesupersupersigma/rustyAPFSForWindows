//! Randomized write test: random operations (including hard links and clones) against an in-memory
//! model, random commits and simulated crashes (dropping the writer without committing), then a full
//! comparison and apfsck.

use rusty_apfs::Container;
use rusty_apfs::write::{Kind, Writer};
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    fn pick<T: Clone>(&mut self, v: &[T]) -> T {
        v[self.below(v.len() as u64) as usize].clone()
    }
}

#[derive(Clone, Debug, PartialEq)]
enum Node {
    Dir,
    File(Vec<u8>),
}

/// Paths map to object ids so hard links share one object; clones get their own.
#[derive(Clone, Default)]
struct Model {
    paths: BTreeMap<String, u64>,
    objs: BTreeMap<u64, Node>,
    next: u64,
}

impl Model {
    fn node(&self, path: &str) -> &Node {
        &self.objs[&self.paths[path]]
    }
    fn is_dir(&self, path: &str) -> bool {
        *self.node(path) == Node::Dir
    }
    fn find_ci(&self, path: &str) -> Option<String> {
        self.paths.keys().find(|k| k.to_lowercase() == path.to_lowercase()).cloned()
    }
    fn has_children(&self, path: &str) -> bool {
        self.paths.keys().any(|k| k.starts_with(&format!("{path}/")))
    }
    fn add(&mut self, path: String, node: Node) {
        self.next += 1;
        self.paths.insert(path, self.next);
        self.objs.insert(self.next, node);
    }
    fn unlink(&mut self, path: &str) {
        let id = self.paths.remove(path).unwrap();
        if !self.paths.values().any(|&i| i == id) {
            self.objs.remove(&id);
        }
    }
}

fn tool(name: &str) -> PathBuf {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tools/bin").join(format!("{name}.exe"));
    assert!(p.exists(), "missing {}: run `python scripts/build-apfsprogs.py`", p.display());
    p
}

fn fsck(p: &Path) {
    let out = Command::new(tool("apfsck")).arg("-cw").arg(p).output().unwrap();
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success() && text.trim().is_empty(), "apfsck on {}:\n{text}", p.display());
}

fn parent_of(path: &str) -> (&str, &str) {
    match path.rfind('/') {
        Some(i) => (&path[..i], &path[i + 1..]),
        None => ("", path),
    }
}

/// `base` is the directory the test works in ("" = volume root); model paths are relative to it.
fn under(base: &str, path: &str) -> String {
    match (base.is_empty(), path.is_empty()) {
        (true, _) => path.to_string(),
        (false, true) => base.to_string(),
        (false, false) => format!("{base}/{path}"),
    }
}

fn ino(w: &Writer, base: &str, path: &str) -> u64 {
    let full = under(base, path);
    if full.is_empty() { 2 } else { w.view(0).unwrap().lookup(&full).unwrap().id }
}

fn open(p: &Path, password: Option<&str>) -> Writer {
    let mut w = Writer::open(p, None).unwrap();
    if let Some(pw) = password {
        w.unlock(0, pw).unwrap();
    }
    w
}

/// apfsck can't check software-encrypted volumes.
fn fsck_unless_encrypted(p: &Path, password: Option<&str>) {
    if password.is_none() {
        fsck(p);
    }
}

/// Compares the image (as our reader sees it) against the model.
fn check(p: &Path, password: Option<&str>, base: &str, model: &Model) {
    let c = Container::open(p).unwrap();
    let mut v = c.volumes().unwrap().remove(0);
    if let Some(pw) = password {
        v.unlock(pw).unwrap();
    }
    let start = if base.is_empty() { 2 } else { v.lookup(base).unwrap().id };
    let mut seen = BTreeMap::new();
    let mut stack = vec![(start, String::new())];
    while let Some((dir, prefix)) = stack.pop() {
        for e in v.read_dir(dir).unwrap() {
            let path = if prefix.is_empty() { e.name.clone() } else { format!("{prefix}/{}", e.name) };
            let inode = v.inode(e.id).unwrap();
            if inode.is_dir() {
                stack.push((e.id, path.clone()));
                seen.insert(path, Node::Dir);
            } else {
                seen.insert(path, Node::File(v.open(&inode).unwrap().read_all().unwrap()));
            }
        }
    }
    for path in model.paths.keys() {
        let (got, want) = (seen.get(path).unwrap_or_else(|| panic!("missing {path:?}")), model.node(path));
        if got != want {
            match (got, want) {
                (Node::File(g), Node::File(w)) => panic!(
                    "{path:?}: {} bytes vs model {} bytes, differ at {:?}",
                    g.len(),
                    w.len(),
                    g.iter().zip(w).position(|(a, b)| a != b)
                ),
                _ => panic!("{path:?}: kind differs"),
            }
        }
    }
    let extra: Vec<_> = seen.keys().filter(|k| !model.paths.contains_key(*k)).collect();
    assert!(extra.is_empty(), "extra entries: {extra:?}");
}

fn run(seed: u64, ops: usize, mib: u64, crashes: bool) {
    let p = std::env::temp_dir().join(format!("rusty-apfs-stress-{seed}-{}.img", std::process::id()));
    std::fs::File::create(&p).unwrap().set_len(mib << 20).unwrap();
    let out = Command::new(tool("mkapfs")).args(["-L", "Stress"]).arg(&p).output().unwrap();
    assert!(out.status.success());
    run_on(&p, None, "", seed, ops, crashes);
    std::fs::remove_file(&p).unwrap();
}

/// Runs the random workload inside directory `base` of volume 0 of image `p`.
fn run_on(p: &Path, password: Option<&str>, base: &str, seed: u64, ops: usize, crashes: bool) {
    let p = p.to_path_buf();

    let mut rng = Rng(seed | 1);
    let mut model = Model::default();
    let mut committed = Model::default();
    // Files whose data changed since the last commit: in-place overwrites survive a crash.
    let mut dirty: HashSet<u64> = HashSet::new();
    let mut w = open(&p, password);
    let names = ["a", "b", "Docs", "photo.jpg", "notes.txt", "x y z", "über", "ÜBER2", "data.bin", "z"];
    let join = |d: &str, n: &str| if d.is_empty() { n.to_string() } else { format!("{d}/{n}") };
    for step in 0..ops {
        let dirs: Vec<String> =
            std::iter::once(String::new()).chain(model.paths.keys().filter(|k| model.is_dir(k)).cloned()).collect();
        let files: Vec<String> = model.paths.keys().filter(|k| !model.is_dir(k)).cloned().collect();
        let all: Vec<String> = model.paths.keys().cloned().collect();
        let new_name = |rng: &mut Rng| format!("{}{}", rng.pick(&names), rng.below(40));
        match rng.below(100) {
            0..=17 => {
                let d = rng.pick(&dirs);
                let name = new_name(&mut rng);
                let path = join(&d, &name);
                let exists = model.find_ci(&path).is_some();
                let dir = rng.below(4) == 0;
                let pid = ino(&w, base, &d);
                let r = w.create(0, pid, &name, if dir { Kind::Dir } else { Kind::File }, 0o644);
                assert_eq!(r.is_ok(), !exists, "create {path:?}: {r:?}");
                if r.is_ok() {
                    model.add(path, if dir { Node::Dir } else { Node::File(vec![]) });
                }
            }
            18..=21 if !files.is_empty() => {
                // hard link or clone an existing file
                let src = rng.pick(&files);
                let d = rng.pick(&dirs);
                let name = new_name(&mut rng);
                let path = join(&d, &name);
                let exists = model.find_ci(&path).is_some();
                let (sid, pid) = (ino(&w, base, &src), ino(&w, base, &d));
                if rng.below(2) == 0 {
                    let r = w.link(0, sid, pid, &name);
                    assert_eq!(r.is_ok(), !exists, "link {src:?} -> {path:?}: {r:?}");
                    if r.is_ok() {
                        let id = model.paths[&src];
                        model.paths.insert(path, id);
                    }
                } else {
                    let r = w.clone_file(0, sid, pid, &name);
                    assert_eq!(r.is_ok(), !exists, "clone {src:?} -> {path:?}: {r:?}");
                    if r.is_ok() {
                        let node = model.node(&src).clone();
                        model.add(path, node);
                    }
                }
            }
            22..=49 if !files.is_empty() => {
                let f = rng.pick(&files);
                let Node::File(data) = model.objs.get_mut(&model.paths[&f]).unwrap() else { unreachable!() };
                let off = match rng.below(4) {
                    0 => data.len() as u64,
                    1 => rng.below(data.len() as u64 + 1),
                    2 => rng.below(300_000),
                    _ => 0,
                };
                let len = [1, 100, 4096, 5000, 70_000][rng.below(5) as usize];
                let bytes: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
                let id = ino(&w, base, &f);
                dirty.insert(id);
                w.write_at(0, id, off, &bytes).unwrap();
                let end = off as usize + len;
                if data.len() < end {
                    data.resize(end, 0);
                }
                data[off as usize..end].copy_from_slice(&bytes);
            }
            50..=58 if !files.is_empty() => {
                let f = rng.pick(&files);
                let Node::File(data) = model.objs.get_mut(&model.paths[&f]).unwrap() else { unreachable!() };
                let size = match rng.below(3) {
                    0 => 0,
                    1 => rng.below(data.len() as u64 + 1),
                    _ => data.len() as u64 + rng.below(200_000),
                };
                let id = ino(&w, base, &f);
                dirty.insert(id);
                w.set_size(0, id, size).unwrap();
                data.resize(size as usize, 0);
            }
            59..=68 if !all.is_empty() => {
                let path = rng.pick(&all);
                let (d, name) = parent_of(&path);
                let nonempty = model.has_children(&path);
                let pid = ino(&w, base, d);
                let r = w.remove(0, pid, name);
                assert_eq!(r.is_ok(), !nonempty, "remove {path:?}: {r:?}");
                if r.is_ok() {
                    model.unlink(&path);
                }
            }
            69..=84 if !all.is_empty() => {
                let src = rng.pick(&all);
                let d = rng.pick(&dirs);
                let name = new_name(&mut rng);
                let dst = join(&d, &name);
                if dst == src || dst.starts_with(&format!("{src}/")) {
                    continue; // into itself
                }
                let target = model.find_ci(&dst);
                let replace = rng.below(2) == 0;
                let (sd, sn) = parent_of(&src);
                let (spid, dpid) = (ino(&w, base, sd), ino(&w, base, &d));
                let r = w.rename(0, spid, sn, dpid, &name, replace);
                let same_obj = target.as_ref().is_some_and(|t| t != &src && model.paths[t] == model.paths[&src]);
                let expect_ok = match &target {
                    None => true,
                    Some(t) if t == &src || same_obj => true,
                    Some(t) => replace && model.is_dir(t) == model.is_dir(&src) && !model.has_children(t),
                };
                assert_eq!(r.is_ok(), expect_ok, "rename {src:?} -> {dst:?} (target {target:?}): {r:?}");
                if r.is_ok() && !same_obj {
                    if let Some(t) = &target
                        && t != &src
                    {
                        model.unlink(t);
                    }
                    let moved: Vec<(String, u64)> = model
                        .paths
                        .iter()
                        .filter(|(k, _)| **k == src || k.starts_with(&format!("{src}/")))
                        .map(|(k, id)| (k.clone(), *id))
                        .collect();
                    for (k, id) in moved {
                        model.paths.remove(&k);
                        model.paths.insert(format!("{dst}{}", &k[src.len()..]), id);
                    }
                }
            }
            85..=94 => {
                w.commit().unwrap();
                committed = model.clone();
                dirty.clear();
            }
            _ if !crashes => {
                w.commit().unwrap();
                committed = model.clone();
                dirty.clear();
            }
            _ => {
                // Crash: drop uncommitted changes and reopen.
                drop(w);
                w = open(&p, password);
                model = committed.clone();
                // Metadata rolls back; data overwritten in place may not. Sizes must match the commit.
                let view = w.view(0).unwrap();
                for path in model.paths.keys().cloned().collect::<Vec<_>>() {
                    let id = model.paths[&path];
                    if let Node::File(want) = model.objs.get_mut(&id).unwrap() {
                        let inode = view.lookup(&under(base, &path)).unwrap();
                        let got = view.open(&inode).unwrap().read_all().unwrap();
                        assert_eq!(got.len(), want.len(), "{path:?} size after crash");
                        if &got != want {
                            assert!(dirty.contains(&inode.id), "{path:?} changed without being written");
                            *want = got;
                        }
                    }
                }
                drop(view);
                committed = model.clone();
                dirty.clear();
            }
        }
        if step % 500 == 499 {
            w.commit().unwrap();
            committed = model.clone();
            dirty.clear();
            drop(w);
            check(&p, password, base, &committed);
            fsck_unless_encrypted(&p, password);
            w = open(&p, password);
        }
    }
    w.commit().unwrap();
    drop(w);
    check(&p, password, base, &model);
    fsck_unless_encrypted(&p, password);
}

#[test]
fn stress_seed_1() {
    run(0x9e37_79b9_7f4a_7c15, 2000, 128, true);
}

#[test]
fn stress_seed_2() {
    run(12345, 2000, 128, true);
}

#[test]
fn stress_no_crashes() {
    run(4242, 1500, 64, false);
}

#[test]
fn stress_small_disk() {
    // A small container exercises the free-queue limits.
    run(777, 1500, 24, true);
}

#[test]
fn stress_encrypted_volume() {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("ignored/testdata/jhfs_encrypted.bin");
    let p = std::env::temp_dir().join(format!("rusty-apfs-stress-enc-{}.img", std::process::id()));
    std::fs::copy(&src, &p).unwrap();
    let mut w = open(&p, Some("password"));
    w.create(0, 2, "stress", Kind::Dir, 0o755).unwrap();
    w.commit().unwrap();
    drop(w);
    run_on(&p, Some("password"), "stress", 99, 1500, true);
    std::fs::remove_file(&p).unwrap();
}
