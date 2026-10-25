"""Download the APFS test images used by `cargo test` into ignored/testdata/.

The images come from fox-it/dissect.apfs (AGPL-3.0), stored there with Git LFS.
They're test data only, so they stay out of this repo.
"""

import gzip
import pathlib
import urllib.request

NAMES = [
    "case_insensitive", "case_insensitive_beta", "case_sensitive", "case_sensitive_beta",
    "corrupt", "encrypted", "jhfs_converted", "jhfs_encrypted", "large", "snapshot",
]
URL = "https://media.githubusercontent.com/media/fox-it/dissect.apfs/main/tests/_data/{}.bin.gz"
OUT = pathlib.Path(__file__).resolve().parent.parent / "ignored" / "testdata"

OUT.mkdir(parents=True, exist_ok=True)
for name in NAMES:
    dest = OUT / f"{name}.bin"
    if dest.exists():
        continue
    req = urllib.request.Request(URL.format(name), headers={"User-Agent": "rusty-apfs-tests"})
    with urllib.request.urlopen(req, timeout=300) as r:
        raw = gzip.decompress(r.read())
    if raw[32:36] != b"NXSB":
        raise SystemExit(f"{name}: downloaded file is not an APFS container")
    dest.write_bytes(raw)
    print(f"{name}: {len(raw):,} bytes")
print(f"test images ready in {OUT}")
