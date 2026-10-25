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
| Physical disks / GPT partitions | done (`apfs list`, needs admin) |
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

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
