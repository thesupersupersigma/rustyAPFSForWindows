"""Build apfsck.exe and mkapfs.exe from linux-apfs/apfsprogs for validating our writes on Windows.

apfsprogs is GPLv2, so it is cloned into the gitignored tools/ dir rather than vendored here.
Our Windows shim (scripts/apfsprogs-compat) is force-included. The only source edits are the upstream bug
fixes listed in FIXES, applied after checkout (git checkout restores the pristine files first).

Needs Visual Studio with the "C++ Clang tools" (clang-cl). Usage: python scripts/build-apfsprogs.py
"""

import pathlib
import subprocess
import sys

REPO = "https://github.com/linux-apfs/apfsprogs.git"
PIN = "1bd1c1c2140d13d1b6d2e03379316572bee70aa3"

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "tools" / "apfsprogs"
BUILD = ROOT / "tools" / "apfsprogs-build"
BIN = ROOT / "tools" / "bin"
COMPAT = ROOT / "scripts" / "apfsprogs-compat"
# Linux headers with no Windows equivalent; compat.h already declares what they would.
EMPTY_HEADERS = ["unistd.h", "sys/mman.h", "sys/ioctl.h", "linux/fs.h", "linux/slab.h", "linux/vmalloc.h"]
TOOLS = {
    "apfsck": "apfsck.c btree.c compress.c crypto.c dir.c extents.c htable.c inode.c key.c object.c "
    "snapshot.c spaceman.c super.c xattr.c",
    "mkapfs": "btree.c dir.c mkapfs.c object.c spaceman.c super.c",
}


# (file, buggy line, fixed line): upstream bugs that make apfsck reject valid volumes.
FIXES = [
    # Directory statistics: file sizes were added to the on-disk total instead of the computed one,
    # so any tracked folder with non-empty files was reported as "wrong total size".
    ("apfsck/inode.c", "parent_stat->ds_total_size += inode->i_dstream->d_size;",
     "parent_stat->ds_child_size += inode->i_dstream->d_size;"),
]


def run(cmd, **kw):
    print(">", cmd if isinstance(cmd, str) else " ".join(map(str, cmd)))
    subprocess.run(cmd, check=True, **kw)


def checkout():
    if not SRC.exists():
        run(["git", "clone", "-q", REPO, str(SRC)])
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=SRC, capture_output=True, text=True, check=True).stdout
    if head.strip() != PIN:
        run(["git", "fetch", "-q", "origin"], cwd=SRC)
        run(["git", "checkout", "-q", PIN], cwd=SRC)
    run(["git", "checkout", "-q", "--", "."], cwd=SRC)
    for rel, old, new in FIXES:
        path = SRC / rel
        text = path.read_text()
        if old not in text:
            sys.exit(f"fix no longer applies to {rel}: {old!r}")
        path.write_text(text.replace(old, new))


def visual_studio():
    vswhere = pathlib.Path(r"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe")
    out = subprocess.run([str(vswhere), "-latest", "-products", "*", "-property", "installationPath"],
                         capture_output=True, text=True, check=True).stdout.strip()
    vs = pathlib.Path(out)
    vcvars = vs / "VC" / "Auxiliary" / "Build" / "vcvars64.bat"
    clang = vs / "VC" / "Tools" / "Llvm" / "x64" / "bin" / "clang-cl.exe"
    if not vcvars.exists() or not clang.exists():
        sys.exit(f"need vcvars64.bat and clang-cl.exe under {vs} (install the 'C++ Clang tools' component)")
    return vcvars, clang


def main():
    checkout()
    vcvars, clang = visual_studio()
    stubs = BUILD / "include"
    for h in EMPTY_HEADERS:
        p = stubs / h
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("/* Empty: compat.h provides the declarations. */\n")
    BIN.mkdir(parents=True, exist_ok=True)

    lib = sorted(str(p) for p in (SRC / "lib").rglob("*.c"))
    for tool, srcs in TOOLS.items():
        (SRC / tool / "version.h").write_text(f'#define GIT_COMMIT\t"{PIN[:8]}"\n')
        objdir = BUILD / tool
        objdir.mkdir(parents=True, exist_ok=True)
        sources = [str(SRC / tool / s) for s in srcs.split()] + lib + [str(COMPAT / "compat.c")]
        flags = [
            "/nologo", "/O2", "/MT", f"/FI{COMPAT / 'compat.h'}", f"/I{COMPAT}", f"/I{COMPAT / 'include'}",
            f"/I{stubs}", f"/I{SRC / 'include'}", "-fno-strict-aliasing", "-Wno-address-of-packed-member",
            "-Wno-macro-redefined", "-Wno-microsoft-anon-tag", "-Wno-pointer-to-int-cast", f"/Fo{objdir.as_posix()}/", f"/Fe{BIN / (tool + '.exe')}",
        ]
        # A response file keeps us under cmd.exe's 8191-character command limit.
        rsp = objdir / "args.rsp"
        rsp.write_text("\n".join(f'"{a}"' for a in flags + sources))
        # vcvars64 sets INCLUDE/LIB for the Windows SDK and CRT; clang-cl does the compiling.
        run(f'call "{vcvars}" >nul && "{clang}" @"{rsp}"', shell=True)
    print(f"built {', '.join(t + '.exe' for t in TOOLS)} in {BIN}")


if __name__ == "__main__":
    main()
