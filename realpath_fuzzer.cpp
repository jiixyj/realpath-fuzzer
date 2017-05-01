#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>

#include <string>

extern "C" char *
__wrap_realpath(const char * __restrict path, char * __restrict resolved);

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
	// printf("data_null: %s|\n", data_null);

	char resolved[PATH_MAX];
	__wrap_realpath(NULL, resolved);
	resolved[0] = '\0';
	__wrap_realpath((char const *)data_null, resolved);

	errno = 0;
	char *res_path = __wrap_realpath((char const *)data_null, NULL);
	int realpath_errno = errno;

	if (res_path) {
		free(res_path);
	}

	delete[] data_null;

	return 0;
}
