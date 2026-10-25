/* Implementations for compat.h. Part of rusty-apfs (GPL-3.0-or-later). */
#include "compat.h"
#include <stdarg.h>
#include <windows.h>
#include <winioctl.h>

#undef open
static int crt_open(const char *path, int flags, int mode)
{
	return _open(path, flags, mode);
}
#define open compat_open

/* mkapfs reads a random UUID string from this Linux procfs file. */
static int uuid_pipe(void)
{
	unsigned char b[16];
	char s[37];
	int fds[2];

	for (int i = 0; i < 16; i += 4) {
		unsigned int r;
		if (rand_s(&r))
			return -1;
		memcpy(b + i, &r, 4);
	}
	b[6] = (b[6] & 0x0f) | 0x40; /* version 4 */
	b[8] = (b[8] & 0x3f) | 0x80; /* RFC 4122 variant */
	snprintf(s, sizeof(s), "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		 b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
	if (_pipe(fds, 64, _O_BINARY))
		return -1;
	_write(fds[1], s, 36);
	_close(fds[1]);
	return fds[0];
}

int compat_open(const char *path, int flags, ...)
{
	int mode = 0;

	if (strcmp(path, "/proc/sys/kernel/random/uuid") == 0)
		return uuid_pipe();
	if (flags & _O_CREAT) {
		va_list ap;
		va_start(ap, flags);
		mode = va_arg(ap, int);
		va_end(ap);
	}
	return crt_open(path, flags | _O_BINARY, mode);
}

static ssize_t rw_at(int fd, void *buf, size_t count, off_t offset, int write)
{
	HANDLE h = (HANDLE)_get_osfhandle(fd);
	OVERLAPPED ov = {0};
	DWORD done = 0;
	BOOL ok;

	if (h == INVALID_HANDLE_VALUE) {
		errno = EBADF;
		return -1;
	}
	if (count > 0x7fffffff)
		count = 0x7fffffff;
	ov.Offset = (DWORD)((unsigned long long)offset & 0xffffffff);
	ov.OffsetHigh = (DWORD)((unsigned long long)offset >> 32);
	ok = write ? WriteFile(h, buf, (DWORD)count, &done, &ov) : ReadFile(h, buf, (DWORD)count, &done, &ov);
	if (!ok) {
		if (!write && GetLastError() == ERROR_HANDLE_EOF)
			return 0;
		errno = EIO;
		return -1;
	}
	return (ssize_t)done;
}

ssize_t pread(int fd, void *buf, size_t count, off_t offset)
{
	return rw_at(fd, buf, count, offset, 0);
}

ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset)
{
	return rw_at(fd, (void *)buf, count, offset, 1);
}

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	char *p;
	size_t got = 0;

	(void)addr;
	(void)prot;
	if (flags & MAP_SHARED) {
		errno = EINVAL; /* shared (write-through) mappings aren't emulated */
		return MAP_FAILED;
	}
	p = calloc(1, length);
	if (!p) {
		errno = ENOMEM;
		return MAP_FAILED;
	}
	if (flags & MAP_ANONYMOUS)
		return p;
	while (got < length) {
		ssize_t n = pread(fd, p + got, length - got, offset + (off_t)got);
		if (n < 0) {
			free(p);
			return MAP_FAILED;
		}
		if (n == 0)
			break; /* like mmap past EOF: the tail reads as zeros */
		got += (size_t)n;
	}
	return p;
}

int munmap(void *addr, size_t length)
{
	(void)length;
	free(addr);
	return 0;
}

int ioctl(int fd, unsigned long request, ...)
{
	GET_LENGTH_INFORMATION info;
	DWORD ret;
	va_list ap;
	unsigned long long *out;

	if (request != BLKGETSIZE64) {
		errno = ENOTTY;
		return -1;
	}
	va_start(ap, request);
	out = va_arg(ap, unsigned long long *);
	va_end(ap);
	if (!DeviceIoControl((HANDLE)_get_osfhandle(fd), IOCTL_DISK_GET_LENGTH_INFO, NULL, 0, &info, sizeof(info),
			     &ret, NULL)) {
		errno = EIO;
		return -1;
	}
	*out = (unsigned long long)info.Length.QuadPart;
	return 0;
}

char *optarg;
int optind = 1, opterr = 1, optopt;

/* Minimal POSIX getopt: short options, grouped flags, "x:" arguments, stops at "--" or a non-option. */
int getopt(int argc, char *const argv[], const char *optstring)
{
	static int pos = 1;
	const char *spec;
	char c;

	if (optind >= argc || argv[optind][0] != '-' || argv[optind][1] == 0)
		return -1;
	if (strcmp(argv[optind], "--") == 0) {
		optind++;
		return -1;
	}
	c = argv[optind][pos];
	spec = strchr(optstring, c);
	if (!spec || c == ':') {
		optopt = c;
		if (opterr)
			fprintf(stderr, "%s: invalid option -- '%c'\n", argv[0], c);
		if (argv[optind][++pos] == 0) {
			optind++;
			pos = 1;
		}
		return '?';
	}
	if (spec[1] == ':') {
		if (argv[optind][pos + 1]) {
			optarg = &argv[optind][pos + 1];
		} else if (optind + 1 < argc) {
			optarg = argv[++optind];
		} else {
			optopt = c;
			if (opterr)
				fprintf(stderr, "%s: option requires an argument -- '%c'\n", argv[0], c);
			optind++;
			pos = 1;
			return '?';
		}
		optind++;
		pos = 1;
		return c;
	}
	if (argv[optind][++pos] == 0) {
		optind++;
		pos = 1;
	}
	return c;
}
