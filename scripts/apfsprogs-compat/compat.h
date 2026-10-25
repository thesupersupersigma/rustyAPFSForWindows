/* Windows shim for building apfsprogs (apfsck, mkapfs) with clang-cl.
 * Force-included (/FI) into every translation unit before any apfsprogs header.
 * Part of rusty-apfs (GPL-3.0-or-later); only used to build the GPLv2 tools locally.
 */
#ifndef APFSPROGS_WIN_COMPAT_H
#define APFSPROGS_WIN_COMPAT_H

#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NONSTDC_NO_DEPRECATE
#define _CRT_RAND_S

/* MSVC's off_t is 32-bit; apfsprogs casts byte offsets on multi-GB disks to off_t. */
#define _OFF_T_DEFINED
typedef long _off_t;
typedef long long off_t;

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <io.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

typedef intptr_t ssize_t;
typedef long long loff_t;

/* 64-bit file sizes from fstat */
#define stat _stat64
#define fstat _fstat64

#ifndef S_IFIFO
#define S_IFIFO 0010000
#endif
#ifndef S_IFCHR
#define S_IFCHR 0020000
#endif
#ifndef S_IFLNK
#define S_IFLNK 0120000
#endif
#ifndef S_IFSOCK
#define S_IFSOCK 0140000
#endif
#ifndef S_IFBLK
#define S_IFBLK 0060000
#endif
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#define S_ISLNK(m) (((m) & S_IFMT) == S_IFLNK)
#define S_ISBLK(m) (((m) & S_IFMT) == S_IFBLK)
#define S_ISCHR(m) (((m) & S_IFMT) == S_IFCHR)
#define S_ISFIFO(m) (((m) & S_IFMT) == S_IFIFO)
#define S_ISSOCK(m) (((m) & S_IFMT) == S_IFSOCK)

/* Every open is binary; also maps the Linux UUID source (see compat.c). */
int compat_open(const char *path, int flags, ...);
#define open compat_open

ssize_t pread(int fd, void *buf, size_t count, off_t offset);
ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset);

/* mmap is only used for private read-only copies of blocks and anonymous buffers. */
#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define MAP_SHARED 0x01
#define MAP_PRIVATE 0x02
#define MAP_ANONYMOUS 0x20
#define MAP_FAILED ((void *)-1)
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int munmap(void *addr, size_t length);

/* Block-device size, implemented with IOCTL_DISK_GET_LENGTH_INFO. */
#define BLKGETSIZE64 0x80081272
int ioctl(int fd, unsigned long request, ...);

#define CLOCK_REALTIME 0
static inline int clock_gettime(int clk, struct timespec *ts)
{
	(void)clk;
	return timespec_get(ts, TIME_UTC) ? 0 : -1;
}

/* Owner of mkapfs's root directory; Windows has no Unix ids, so use root's. */
static inline unsigned int geteuid(void) { return 0; }
static inline unsigned int getegid(void) { return 0; }

extern char *optarg;
extern int optind, opterr, optopt;
int getopt(int argc, char *const argv[], const char *optstring);

#endif /* APFSPROGS_WIN_COMPAT_H */
