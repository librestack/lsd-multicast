#include "auth.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

ssize_t pack_data(struct iovec *data, struct iovec *iovs[], int iov_count,
		uint8_t op, uint8_t flags)
{
	void *ptr;
	uint64_t n;
	if (!data) {
		errno = EINVAL;
		return -1;
	}
	/* calculate length */
	data->iov_len = 1;
	for (int i = 0; i < iov_count; i++) {
		data->iov_len += iovs[i]->iov_len + 1;
		for (n = htole64(iovs[i]->iov_len); n > 0x7f; n >>= 7)
			(data->iov_len)++;
	}
	ptr = data->iov_base = calloc(1, data->iov_len + 1);
	memset(ptr++, op, 1);
	memset(ptr++, flags, 1);
	for (int i = 0; i < iov_count; i++) {
		/* encode length as bytes with 7 bits + overflow bit */
		for (n = htole64(iovs[i]->iov_len); n > 0x7f; n >>= 7)
			memset(ptr++, 0x80 | n, 1);
		memset(ptr++, n, 1);
		memcpy(ptr, iovs[i]->iov_base, iovs[i]->iov_len);
		ptr += iovs[i]->iov_len;
	}
	return data->iov_len;
}

ssize_t unpack_data(struct iovec *data, struct iovec iovs[], int iov_count,
		uint8_t *op, uint8_t *flags)
{
	void *ptr = data->iov_base;
	size_t len;
	*op = ((auth_opcode_t *)ptr++)[0];
	*flags = ((uint8_t *)ptr++)[0];
	for (int i = 0; ptr < data->iov_base + data->iov_len; i++) {
		uint64_t n = 0, shift = 0;
		uint8_t b;
		do {
			b = ((uint8_t *)ptr++)[0];
			n |= (b & 0x7f) << shift;
			shift += 7;
		} while (b & 0x80);
		len = (size_t)le64toh(n);
		iovs[i].iov_len = len;
		iovs[i].iov_base = ptr;
		ptr += len;
	}
	return data->iov_len;
}
