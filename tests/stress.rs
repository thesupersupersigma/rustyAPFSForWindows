//! Randomized write test: random operations against an in-memory model, random commits and simulated
//! crashes (dropping the writer without committing), then a full comparison and apfsck.

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
}

#[derive(Clone, Debug, PartialEq)]
enum Node {
    Dir,
    File(Vec<u8>),
}

type Model = BTreeMap<String, Node>; // "/"-joined path from the root -> node

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

fn ino(w: &Writer, path: &str) -> u64 {
    if path.is_empty() { 2 } else { w.view(0).unwrap().lookup(path).unwrap().id }
}

/// Compares the image (as our reader sees it) against the model.
fn check(p: &Path, model: &Model) {
    let c = Container::open(p).unwrap();
    let v = c.volumes().unwrap().remove(0);
    let mut seen = Model::new();
    let mut stack = vec![(2u64, String::new())];
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
    for (k, want) in model {
        let got = seen.get(k).unwrap_or_else(|| panic!("missing {k:?}"));
        if got != want {
            match (got, want) {
                (Node::File(g), Node::File(w)) => panic!(
                    "{k:?}: {} bytes vs model {} bytes, differ at {:?}",
                    g.len(),
                    w.len(),
                    g.iter().zip(w).position(|(a, b)| a != b)
                ),
                _ => panic!("{k:?}: kind differs"),
            }
        }
    }
    assert_eq!(
        seen.len(),
        model.len(),
        "extra entries: {:?}",
        seen.keys().filter(|k| !model.contains_key(*k)).collect::<Vec<_>>()
    );
}

fn run(seed: u64, ops: usize, mib: u64, crashes: bool) {
    let p = std::env::temp_dir().join(format!("rusty-apfs-stress-{seed}-{}.img", std::process::id()));
    std::fs::File::create(&p).unwrap().set_len(mib << 20).unwrap();
    let out = Command::new(tool("mkapfs")).args(["-L", "Stress"]).arg(&p).output().unwrap();
    assert!(out.status.success());

    let mut rng = Rng(seed | 1);
    let mut model = Model::new();
    let mut committed = Model::new();
    // Files whose data changed since the last commit: in-place overwrites survive a crash.
    let mut dirty: HashSet<u64> = HashSet::new();
    let mut w = Writer::open(&p, None).unwrap();
    let names = ["a", "b", "Docs", "photo.jpg", "notes.txt", "x y z", "über", "ÜBER2", "data.bin", "z"];
    for step in 0..ops {
        let dirs: Vec<String> = std::iter::once(String::new())
            .chain(model.iter().filter(|(_, n)| **n == Node::Dir).map(|(k, _)| k.clone()))
            .collect();
        let files: Vec<String> =
            model.iter().filter(|(_, n)| matches!(n, Node::File(_))).map(|(k, _)| k.clone()).collect();
        let join = |d: &str, n: &str| if d.is_empty() { n.to_string() } else { format!("{d}/{n}") };
        match rng.below(100) {
            0..=19 => {
                // create a file or directory
                let d = dirs[rng.below(dirs.len() as u64) as usize].clone();
                let name = format!("{}{}", names[rng.below(names.len() as u64) as usize], rng.below(40));
                let path = join(&d, &name);
                let exists = model.keys().any(|k| k.to_lowercase() == path.to_lowercase());
                let dir = rng.below(4) == 0;
                let pid = ino(&w, &d);
                let r = w.create(0, pid, &name, if dir { Kind::Dir } else { Kind::File }, 0o644);
                assert_eq!(r.is_ok(), !exists, "create {path:?}: {r:?}");
                if r.is_ok() {
                    model.insert(path, if dir { Node::Dir } else { Node::File(vec![]) });
                }
            }
            20..=49 if !files.is_empty() => {
                // write somewhere, sometimes far past the end
                let f = files[rng.below(files.len() as u64) as usize].clone();
                let Node::File(data) = model.get_mut(&f).unwrap() else { unreachable!() };
                let off = match rng.below(4) {
                    0 => data.len() as u64,
                    1 => rng.below(data.len() as u64 + 1),
                    2 => rng.below(300_000),
                    _ => 0,
                };
                let len = [1, 100, 4096, 5000, 70_000][rng.below(5) as usize];
                let bytes: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
                let id = ino(&w, &f);
                dirty.insert(id);
                w.write_at(0, id, off, &bytes).unwrap();
                let end = off as usize + len;
                if data.len() < end {
                    data.resize(end, 0);
                }
                data[off as usize..end].copy_from_slice(&bytes);
            }
            50..=59 if !files.is_empty() => {
                // truncate or extend
                let f = files[rng.below(files.len() as u64) as usize].clone();
                let Node::File(data) = model.get_mut(&f).unwrap() else { unreachable!() };
                let size = match rng.below(3) {
                    0 => 0,
                    1 => rng.below(data.len() as u64 + 1),
                    _ => data.len() as u64 + rng.below(200_000),
                };
                let id = ino(&w, &f);
                dirty.insert(id);
                w.set_size(0, id, size).unwrap();
                data.resize(size as usize, 0);
            }
            60..=69 => {
                // remove a file or an (empty) directory
                let all: Vec<String> = model.keys().cloned().collect();
                if all.is_empty() {
                    continue;
                }
                let path = all[rng.below(all.len() as u64) as usize].clone();
                let (d, name) = parent_of(&path);
                let nonempty = model.keys().any(|k| k.starts_with(&format!("{path}/")));
                let pid = ino(&w, d);
                let r = w.remove(0, pid, name);
                assert_eq!(r.is_ok(), !nonempty, "remove {path:?}: {r:?}");
                if r.is_ok() {
                    model.remove(&path);
                }
            }
            70..=84 => {
                // rename/move, sometimes replacing
                let all: Vec<String> = model.keys().cloned().collect();
                if all.is_empty() {
                    continue;
                }
                let src = all[rng.below(all.len() as u64) as usize].clone();
                let d = dirs[rng.below(dirs.len() as u64) as usize].clone();
                let name = format!("{}{}", names[rng.below(names.len() as u64) as usize], rng.below(40));
                let dst = join(&d, &name);
                if dst == src || dst.starts_with(&format!("{src}/")) {
                    continue; // into itself
                }
                let target = model.keys().find(|k| k.to_lowercase() == dst.to_lowercase()).cloned();
                let replace = rng.below(2) == 0;
                let (sd, sn) = parent_of(&src);
                let (spid, dpid) = (ino(&w, sd), ino(&w, &d));
                let r = w.rename(0, spid, sn, dpid, &name, replace);
                let expect_ok = match &target {
                    None => true,
                    Some(t) if t == &src => true,
                    Some(t) => {
                        replace
                            && (model[t] == Node::Dir) == (model[&src] == Node::Dir)
                            && !model.keys().any(|k| k.starts_with(&format!("{t}/")))
                    }
                };
                assert_eq!(r.is_ok(), expect_ok, "rename {src:?} -> {dst:?} (target {target:?}): {r:?}");
                if r.is_ok() {
                    if let Some(t) = &target
                        && t != &src
                    {
                        model.remove(t);
                    }
                    let moved: Vec<(String, Node)> = model
                        .iter()
                        .filter(|(k, _)| **k == src || k.starts_with(&format!("{src}/")))
                        .map(|(k, n)| (k.clone(), n.clone()))
                        .collect();
                    for (k, n) in moved {
                        model.remove(&k);
                        model.insert(format!("{dst}{}", &k[src.len()..]), n);
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
                w = Writer::open(&p, None).unwrap();
                model = committed.clone();
                // Metadata rolls back; data overwritten in place may not. Sizes must match the commit.
                let view = w.view(0).unwrap();
                for (path, node) in model.iter_mut() {
                    if let Node::File(want) = node {
                        let inode = view.lookup(path).unwrap();
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
            check(&p, &committed);
            fsck(&p);
            w = Writer::open(&p, None).unwrap();
        }
    }
    w.commit().unwrap();
    drop(w);
    check(&p, &model);
    fsck(&p);
    std::fs::remove_file(&p).unwrap();
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
    // A small container exercises the free-queue limits and full-disk handling.
    run(777, 1500, 24, true);
}
