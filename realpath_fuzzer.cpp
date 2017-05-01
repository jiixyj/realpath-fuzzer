#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <sys/stat.h>

#include <string>

#define RANDOMIZE 50

extern "C" char *
fuzz_realpath(const char * __restrict path, char * __restrict resolved);

extern "C" void *__real_malloc(size_t);
extern "C" void *
__wrap_malloc(size_t size)
{
	if (RANDOMIZE && !(rand() % RANDOMIZE)) {
		return NULL;
	} else {
		return __real_malloc(size);
	}
}

extern "C" char * __real_getcwd(char *buf, size_t size);
extern "C" char *
__wrap_getcwd(char *buf, size_t size)
{
	if (RANDOMIZE && !(rand() % RANDOMIZE)) {
		return NULL;
	} else {
		if (strlcpy(buf, "/tmp", size) >= size) {
			errno = ERANGE;
			return NULL;
		}
		return buf;
	}
}

extern "C" ssize_t __real_readlink(const char *path, char *buf, size_t bufsiz);
extern "C" ssize_t
__wrap_readlink(const char *path, char *buf, size_t bufsiz)
{
	int r = rand() % RANDOMIZE;
	if (r <= 1) {
		errno = EIO;
		return -1;
	} else if (r <= 3) {
		errno = EINVAL;
		return -1;
	} else if (r <= 5) {
		errno = ENOENT;
		return -1;
	} else if (r <= 6) {
		return 0;
	} else if (r <= 7) {
		return (ssize_t)bufsiz;
	} else if (r <= 8) {
		strcpy(buf, path);
		return strlen(path);
	} else {
		if (bufsiz >= 1023) {
			if (r <= 10) {
				memset(buf, 'a', 1023);
				buf[1022] = '/';
				return 1023;
			} else {
				memset(buf, 'a', 32);
				buf[31] = '/';
				return 32;
			}
		}
		errno = EIO;
		return -1;
	}
}

extern "C" int __real_lstat(const char *path, struct stat *sb);
extern "C" int
__wrap_lstat(const char *path, struct stat *sb)
{
	int r = rand() % RANDOMIZE;
	if (r == 0) {
		errno = EIO;
		return -1;
	} else if (r <= 1) {
		sb->st_mode = 0100000;
		return 0;
	} else if (r <= 4) {
		sb->st_mode = 0040000;
		return 0;
	} else {
		sb->st_mode = 0120000;
		return 0;
	}
}


extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < sizeof(unsigned)) {
		return 0;
	}

	unsigned seed;
	memcpy(&seed, data, sizeof(unsigned));
	srand(seed);

	uint8_t *data_null = new uint8_t[size - sizeof(unsigned) + 1];
	memcpy(data_null, data + sizeof(unsigned), size - sizeof(unsigned));
	data_null[size - sizeof(unsigned)] = 0;

	for (int i = 0; i < 16; ++i) {
		char resolved[PATH_MAX];
		fuzz_realpath(NULL, resolved);
		resolved[0] = '\0';
		fuzz_realpath((char const *)data_null, resolved);

		errno = 0;
		char *res_path = fuzz_realpath((char const *)data_null, NULL);
		int realpath_errno = errno;

		if (res_path) {
			free(res_path);
		}
	}

	delete[] data_null;

	return 0;
}
