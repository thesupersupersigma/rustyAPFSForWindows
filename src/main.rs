use rusty_apfs::{Container, Volume};
use std::io::{self, Write};
use std::process::ExitCode;

const USAGE: &str = "usage: apfs list                      (APFS partitions on physical disks; needs admin)
       apfs <image|disk> info [--partition N] [--password PW]
       apfs <image|disk> ls  [path] [--volume N] [--snapshot NAME] [--password PW]
       apfs <image|disk> cat <path> [--volume N] [--snapshot NAME] [--password PW]
       apfs <image|disk> mount <X: | new-folder> [--volume N] [--snapshot NAME] [--password PW] [--read-only]
                      (read-write unless --read-only, a snapshot, or a volume we can't write)
       apfs [image|disk] mount-all [--read-only] [--password PW]
                      (every volume on free drive letters; without a path, every APFS disk; needs admin)";

fn main() -> ExitCode {
    match run(std::env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(mut args: Vec<String>) -> io::Result<()> {
    let opt = |args: &mut Vec<String>, flag: &str| -> Option<String> {
        let i = args.iter().position(|a| a == flag)?;
        args.remove(i);
        (i < args.len()).then(|| args.remove(i))
    };
    let vol_idx: usize = opt(&mut args, "--volume").map_or(Ok(0), |v| v.parse()).map_err(|_| usage())?;
    let snap = opt(&mut args, "--snapshot");
    let partition: Option<usize> = opt(&mut args, "--partition").map(|p| p.parse()).transpose().map_err(|_| usage())?;
    if args.first().map(String::as_str) == Some("list") {
        return list();
    }
    #[cfg(windows)]
    if args.first().map(String::as_str) == Some("mount-all") {
        let read_only = args.iter().position(|a| a == "--read-only").map(|i| args.remove(i)).is_some();
        let password = opt(&mut args, "--password");
        return mount_all(physical_containers(), read_only, password.as_deref());
    }
    let password = opt(&mut args, "--password");
    let read_only = args.iter().position(|a| a == "--read-only").map(|i| args.remove(i)).is_some();
    let [image, cmd, rest @ ..] = args.as_slice() else { return Err(usage()) };

    #[cfg(windows)]
    if cmd == "mount-all" {
        return mount_all(vec![(image.clone(), partition)], read_only, password.as_deref());
    }
    #[cfg(windows)]
    if cmd == "mount" && !read_only && snap.is_none() {
        let mountpoint = rest.first().ok_or_else(usage)?;
        match rusty_apfs::write::Writer::open(image, partition) {
            Ok(w) if vol_idx >= w.volume_count() => return Err(io::Error::other(format!("no volume {vol_idx}"))),
            Ok(mut w) => {
                if let Some(pw) = &password
                    && w.is_locked(vol_idx)
                {
                    w.unlock(vol_idx, pw)?;
                }
                match w.read_only_reason(vol_idx) {
                    None => return rusty_apfs::mount::mount_rw(w, vol_idx, mountpoint),
                    Some(why) => eprintln!("mounting read-only: {why}"),
                }
            }
            Err(e) => eprintln!("mounting read-only: {e}"),
        }
    }

    let c = match partition {
        Some(n) => Container::open_partition(image, n)?,
        None => Container::open(image)?,
    };
    // Leaked: it lives for the whole process, and the mount needs a 'static borrow.
    let c: &'static Container = Box::leak(Box::new(c));
    if cmd == "info" {
        return info(c, password.as_deref());
    }
    let vols = c.volumes()?;
    let mut vol = vols.into_iter().nth(vol_idx).ok_or_else(|| io::Error::other(format!("no volume {vol_idx}")))?;
    if vol.is_locked() {
        let pw = password.ok_or_else(|| io::Error::other("volume is encrypted: pass --password"))?;
        vol.unlock(&pw)?;
    }
    if let Some(name) = snap {
        let s = vol
            .snapshots()?
            .into_iter()
            .find(|s| s.name == name)
            .ok_or_else(|| io::Error::other(format!("no snapshot {name:?}")))?;
        vol = vol.snapshot(&s)?;
    }
    let path = rest.first().map_or("/", String::as_str);
    match cmd.as_str() {
        "ls" => ls(&vol, path),
        "dump" => io::stdout().lock().write_all(vol.dump()?.as_bytes()),
        "cat" => {
            let f = vol.open(&vol.lookup(path)?)?;
            io::stdout().lock().write_all(&f.read_all()?)
        }
        #[cfg(windows)]
        "mount" => rusty_apfs::mount::mount(c, vol, rest.first().ok_or_else(usage)?),
        _ => Err(usage()),
    }
}

/// Mounts every readable volume of each container on free drive letters, writable where possible.
#[cfg(windows)]
fn mount_all(containers: Vec<(String, Option<usize>)>, read_only: bool, password: Option<&str>) -> io::Result<()> {
    use rusty_apfs::mount;
    use std::sync::{Arc, Mutex};
    let mut letters = mount::free_drive_letters().into_iter();
    let mut mounts = vec![];
    for (path, partition) in containers {
        let writer = if read_only { None } else { rusty_apfs::write::Writer::open(&path, partition).ok() };
        if let Some(mut w) = writer {
            let n = w.volume_count();
            for v in 0..n {
                if let Some(pw) = password
                    && w.is_locked(v)
                    && let Err(e) = w.unlock(v, pw)
                {
                    eprintln!("{path} volume {v}: {e}");
                }
            }
            let w = Arc::new(Mutex::new(w));
            for v in 0..n {
                let Some(mp) = letters.next() else { break };
                match mount::through_writer(&w, v, &mp) {
                    Ok(m) => mounts.push(m),
                    Err(e) => eprintln!("{path} volume {v}: skipped ({e})"),
                }
            }
            continue;
        }
        let c = match partition {
            Some(n) => Container::open_partition(&path, n),
            None => Container::open(&path),
        };
        let c: &'static Container = match c {
            Ok(c) => Box::leak(Box::new(c)),
            Err(e) => {
                eprintln!("{path}: {e}");
                continue;
            }
        };
        for (v, mut vol) in c.volumes()?.into_iter().enumerate() {
            if vol.is_locked() {
                match password {
                    Some(pw) if vol.unlock(pw).is_ok() => {}
                    _ => {
                        eprintln!("{path} volume {v} ({:?}): encrypted, skipped (pass --password)", vol.name);
                        continue;
                    }
                }
            }
            let Some(mp) = letters.next() else { break };
            match mount::read_only(c, vol, &mp) {
                Ok(m) => mounts.push(m),
                Err(e) => eprintln!("{path} volume {v}: skipped ({e})"),
            }
        }
    }
    mount::serve(mounts)
}

/// Every APFS container on the physical disks.
#[cfg(windows)]
fn physical_containers() -> Vec<(String, Option<usize>)> {
    let mut out = vec![];
    for n in 0..32 {
        let disk = format!(r"\\.\PhysicalDrive{n}");
        match rusty_apfs::apfs_partitions(&disk) {
            Ok(parts) => out.extend((0..parts.len()).map(|i| (disk.clone(), Some(i)))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => eprintln!("{disk}: {e}"),
        }
    }
    out
}

fn info(c: &Container, password: Option<&str>) -> io::Result<()> {
    println!("block size {}, checkpoint xid {}", c.block_size, c.xid);
    for s in &c.skipped {
        println!("  {s}");
    }
    for (i, mut v) in c.volumes()?.into_iter().enumerate() {
        println!(
            "volume {i}: {:?} incompat={:#x}{}",
            v.name,
            v.incompatible_features,
            if v.encrypted { " (encrypted)" } else { "" }
        );
        if let (true, Some(pw)) = (v.is_locked(), password) {
            v.unlock(pw)?;
        }
        if !v.is_locked() {
            for s in v.snapshots()? {
                println!("  snapshot {:?} xid={}", s.name, s.xid);
            }
        }
    }
    Ok(())
}

fn ls(vol: &Volume, path: &str) -> io::Result<()> {
    let dir = vol.lookup(path)?;
    let mut out = io::stdout().lock();
    for e in vol.read_dir(dir.id)? {
        let ino = vol.inode(e.id)?;
        let kind = if ino.is_dir() {
            'd'
        } else if ino.is_symlink() {
            'l'
        } else {
            '-'
        };
        let size = if ino.is_compressed() { vol.open(&ino)?.size } else { ino.size };
        write!(out, "{kind} {:o} {:>10} {}", ino.mode & 0o7777, size, e.name)?;
        if ino.is_symlink() {
            write!(out, " -> {}", vol.readlink(&ino)?)?;
        }
        writeln!(out)?;
    }
    Ok(())
}

fn list() -> io::Result<()> {
    for n in 0..32 {
        let disk = format!(r"\\.\PhysicalDrive{n}");
        match rusty_apfs::apfs_partitions(&disk) {
            Ok(parts) => {
                for (i, p) in parts.iter().enumerate() {
                    let gib = p.size as f64 / (1u64 << 30) as f64;
                    println!("{disk} --partition {i}: {:?} {gib:.1} GiB at byte {}", p.name, p.offset);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => println!("{disk}: {e}"),
        }
    }
    Ok(())
}

fn usage() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, USAGE)
}
