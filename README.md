# rustyAPFS for Windows

An open-source APFS (Apple File System) reader for Windows, written in Rust. The goal is full
read/write access to Mac-formatted drives from Windows, mounted as a normal drive letter.

Built from Apple's public [Apple File System Reference](https://developer.apple.com/support/downloads/Apple-File-System-Reference.pdf).

## Status

| Feature | State |
|---|---|
| Containers, checkpoints (with fallback past corrupt ones), object maps | done |
| Volumes, directories, files, sparse files, hard links, symlinks | done |
| Extended attributes (inline and stream) | done |
| Compressed files (zlib, LZVN, LZFSE, inline and resource fork) | done |
| Snapshots (read-only views) | done |
| Encrypted volumes | not yet (detected and refused) |
| Physical disks / GPT partitions | not yet (disk images only) |
| Mounting as a drive letter (WinFsp) | not yet |
| Writing | not yet |

## Try it

Building needs `libclang` for the WinFsp bindings. Visual Studio ships it; point `LIBCLANG_PATH` at it, e.g.
`C:\Program Files\Microsoft Visual Studio\18\Community\VC\Tools\Llvm\x64\bin`.

```
cargo build --release
target/release/apfs <image> info
target/release/apfs <image> ls dir
target/release/apfs <image> cat dir/file
target/release/apfs <image> ls / --snapshot "Snapshot 3"
```

In Git Bash, set `MSYS_NO_PATHCONV=1` first, or it rewrites a bare `/` into a Windows path.

## Tests

```
python scripts/fetch-testdata.py   # downloads test images into ignored/testdata/
cargo test --release
```

The test images come from [dissect.apfs](https://github.com/fox-it/dissect.apfs).

### Checking images with apfsck and mkapfs

To validate what we write without a Mac, we use `apfsck` (checker) and `mkapfs` (formatter) from
[linux-apfs/apfsprogs](https://github.com/linux-apfs/apfsprogs), built natively for Windows. They're GPLv2, so
the script clones a pinned commit into `tools/` (gitignored) and builds it with a small shim
(`scripts/apfsprogs-compat`) instead of vendoring the source. Needs Visual Studio's "C++ Clang tools" (clang-cl).

```
python scripts/build-apfsprogs.py               # -> tools/bin/apfsck.exe, tools/bin/mkapfs.exe

# mkapfs formats an existing file: create it at the size you want first.
python -c "open('ignored/new.img','wb').truncate(64 << 20)"
tools/bin/mkapfs.exe -L "My Volume" ignored/new.img   # case-insensitive by default
#   -s  case-sensitive (normalization-insensitive)    -s -z  case- and normalization-sensitive
tools/bin/apfsck.exe -cw ignored/new.img              # exit code 0 = clean
```

`apfsck` flags: `-c` reports leftovers of an unclean unmount, `-w` reports odd-but-legal states, `-u` lists
features it can't check. Known false alarms on the dissect images: LZVN/LZFSE resource-fork compression
("block metadata is too big"), macOS-beta images ("incompatible resource fork flags"), and the `jhfs_*` images,
which are 512 bytes shorter than their container ("too many blocks for device"). Software-encrypted volumes
aren't supported by apfsck.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
