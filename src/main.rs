use rusty_apfs::{Container, Volume};
use std::io::{self, Write};
use std::process::ExitCode;

const USAGE: &str = "usage: apfs <image> info
       apfs <image> ls  [path] [--volume N] [--snapshot NAME]
       apfs <image> cat <path> [--volume N] [--snapshot NAME]
       apfs <image> mount <X: | new-folder> [--volume N] [--snapshot NAME]";

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
    let [image, cmd, rest @ ..] = args.as_slice() else { return Err(usage()) };

    // Leaked: it lives for the whole process, and the mount needs a 'static borrow.
    let c: &'static Container = Box::leak(Box::new(Container::open(image)?));
    if cmd == "info" {
        return info(c);
    }
    let vols = c.volumes()?;
    let mut vol = vols.into_iter().nth(vol_idx).ok_or_else(|| io::Error::other(format!("no volume {vol_idx}")))?;
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
        "cat" => {
            let f = vol.open(&vol.lookup(path)?)?;
            io::stdout().lock().write_all(&f.read_all()?)
        }
        #[cfg(windows)]
        "mount" => rusty_apfs::mount::mount(c, vol, rest.first().ok_or_else(usage)?),
        _ => Err(usage()),
    }
}

fn info(c: &Container) -> io::Result<()> {
    println!("block size {}, checkpoint xid {}", c.block_size, c.xid);
    for s in &c.skipped {
        println!("  {s}");
    }
    for (i, v) in c.volumes()?.iter().enumerate() {
        println!(
            "volume {i}: {:?} incompat={:#x}{}",
            v.name,
            v.incompatible_features,
            if v.encrypted { " (encrypted)" } else { "" }
        );
        if !v.encrypted {
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

fn usage() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, USAGE)
}
