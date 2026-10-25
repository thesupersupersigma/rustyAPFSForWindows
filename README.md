# rustyAPFS for Windows

Read and write Mac-formatted (APFS) drives on Windows. Plug in a Mac drive, mount it as a drive letter,
and use it from Explorer like any other disk. Free, open source (GPL-3.0), written in Rust.

It's built from Apple's public [Apple File System Reference](https://developer.apple.com/support/downloads/Apple-File-System-Reference.pdf),
and every write path is checked with an independent APFS checker (`apfsck`, see [Testing](#testing)).

## What works

| | |
|---|---|
| Mount APFS volumes as drive letters | yes, read-write (via [WinFsp](https://winfsp.dev)) |
| Physical disks (GPT partitions) and disk image files | yes (physical disks need administrator rights) |
| Create, edit, append, truncate, rename, move, delete files and folders | yes |
| Read-only / hidden attributes, timestamps | yes (mapped to macOS permissions and flags) |
| Compressed files (zlib, LZVN, LZFSE) | read; decompressed on first write |
| Hard links, clones (copy-on-write), sparse files, symlinks | yes (symlinks show as Windows symlinks) |
| Folder size tracking (directory statistics) | kept up to date |
| Encrypted volumes (password / FileVault-style) | read with `--password` |
| Snapshots (Time Machine local snapshots) | read-only, can mount any snapshot |
| Volumes with snapshots, sealed system volumes, Fusion drives | read-only (like Paragon's product) |
| Hardware-encrypted (T2 / Apple silicon internal) disks | not readable from Windows |

## Install

1. Install [WinFsp](https://github.com/winfsp/winfsp/releases) (the `.msi`).
2. Get `apfs.exe` and `apfs-gui.exe` (build them, see below).

## Use it

**App:** run `apfs-gui.exe`. It lists the APFS volumes on your disks (it offers to restart as administrator,
which reading physical disks needs) and any image you open. Press **Mount** to get a drive letter; tick
**Read-only** first if you only want to look. **Unmount** before unplugging the drive.

**Command line:**

```
apfs list                                   # APFS partitions on your disks (run as administrator)
apfs mount-all                              # mount every APFS volume on every disk; Ctrl+C unmounts
apfs \\.\PhysicalDrive1 mount X:            # one disk's first APFS volume on X:
apfs mac.img mount X: --read-only           # an image, read-only
apfs mac.img mount X: --snapshot "com.apple.TimeMachine.2026-10-01-120000.local"
apfs mac.img info                           # volumes, snapshots
apfs mac.img ls Users/me                    # list a folder
apfs mac.img cat Users/me/notes.txt         # print a file
```

Options: `--volume N` (default 0), `--partition N` (which APFS partition of a disk), `--password PW`
(encrypted volumes). In Git Bash, set `MSYS_NO_PATHCONV=1` or it rewrites a bare `/` into a Windows path.

### Things to know

- **Unmount before unplugging.** Changes are saved about once a second and on unmount. If the drive is
  pulled or Windows crashes, you lose at most the last second of changes and the volume stays consistent
  (APFS writes metadata copy-on-write). Like most file systems, data overwritten in place during that last
  second may be partly new.
- Only one program can write to a disk at a time; a second writer (including another APFS driver, such as
  Paragon's) is refused while a volume is mounted read-write.
- File names are limited to 255 bytes of UTF-8 (macOS's limit), so very long non-Latin names are refused.
- Files copied from Windows get owner "unknown" (uid/gid 99), like files on any external Mac drive.

## Build

Needs Rust and Visual Studio (for the linker and `libclang`, which the WinFsp bindings use). Point
`LIBCLANG_PATH` at Visual Studio's copy, e.g.
`C:\Program Files\Microsoft Visual Studio\18\Community\VC\Tools\Llvm\x64\bin`.

```
cargo build --release                    # target/release/apfs.exe
cargo build --release --features gui     # also target/release/apfs-gui.exe
```

## Testing

```
python scripts/fetch-testdata.py      # Apple-made test images (from dissect.apfs) -> ignored/testdata/
python scripts/build-apfsprogs.py     # apfsck + mkapfs for Windows -> tools/bin/
cargo test --release
```

- Reader tests check every file, link, xattr, compression format, snapshot and corrupt-checkpoint case in
  the dissect.apfs images against the values its test suite records.
- Write tests format fresh volumes with `mkapfs` (and copy Apple-made ones), change them through the writer,
  then check the result with our reader **and with `apfsck`**. A randomized stress test runs thousands of
  operations (including hard links, clones, crashes without commit) against an in-memory model.
- Ignored tests: `bench` (speed) and `big_container_with_cabs` (needs a multi-TB sparse image,
  `RUSTY_APFS_BIG_IMAGE=<mkapfs-formatted file>`).

### apfsck and mkapfs

`apfsck` (checker) and `mkapfs` (formatter) come from [linux-apfs/apfsprogs](https://github.com/linux-apfs/apfsprogs).
They're GPLv2, so the script clones a pinned commit into `tools/` (gitignored), applies one upstream bug fix
(listed in the script) and builds it with our Windows shim (`scripts/apfsprogs-compat`). Needs Visual
Studio's "C++ Clang tools" (clang-cl).

```
python -c "open('ignored/new.img','wb').truncate(64 << 20)"
tools/bin/mkapfs.exe -L "My Volume" ignored/new.img   # -s case-sensitive, -s -z also normalization-sensitive
tools/bin/apfsck.exe -cw ignored/new.img              # exit code 0 = clean
```

Known false alarms on the dissect images: LZVN/LZFSE resource-fork compression ("block metadata is too
big"), macOS-beta images ("incompatible resource fork flags"), and the `jhfs_*` images, which are 512 bytes
shorter than their container. apfsck can't check software-encrypted volumes.

## How it's put together

| | |
|---|---|
| `src/container.rs`, `device.rs` | checkpoints, object maps, GPT, aligned disk I/O |
| `src/btree.rs`, `volume.rs`, `compress.rs`, `crypto.rs` | reading trees, files, compression, encryption |
| `src/write/` | the writer: copy-on-write B-trees, space manager, checkpoints, file operations |
| `src/mount.rs` | WinFsp file system (read-only and read-write) |
| `src/main.rs`, `src/bin/apfs-gui.rs` | command line and desktop app |

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
