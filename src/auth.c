#include "auth.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

void * auth_pack_field(struct iovec *iov, void *ptr)
{
	if (!iov)
		memset(ptr++, 0, 1);
	else {
		memcpy(ptr++, &iov->iov_len, 1);
		memcpy(ptr, iov->iov_base, iov->iov_len);
		ptr += iov->iov_len;
	}
	return ptr;
}

ssize_t auth_pack(struct iovec *data, struct iovec *iovs[], int iov_count)
{
	void * ptr;
	if (!data) {
		errno = EINVAL;
		return -1;
	}
	if ((!iovs[AUTH_USER]) && (!iovs[AUTH_MAIL])) { /* username or email required */
		errno = EINVAL;
		return -1;
	}
	for (int i = 0; i < iov_count; i++) {
		if (iovs[i] && iovs[i]->iov_len > UCHAR_MAX) {
			errno = E2BIG;
			return -1;
		}
	}
	data->iov_len = iov_count + 1; /* n char for lengths + opcode */
	for (int i = 0; i < iov_count; i++) {
		if (iovs[i]) data->iov_len += iovs[i]->iov_len;
	}
	ptr = data->iov_base = malloc(data->iov_len);
	memset(ptr++, AUTH_OP_NOOP, 1);
	for (int i = 0; i < iov_count; i++) {
		ptr = auth_pack_field(iovs[i], ptr);
	}
	return data->iov_len;
}

ssize_t auth_pack_next(struct iovec *data, struct iovec *iovs[], int iov_count,
		auth_opcode_t op, uint8_t flags)
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

ssize_t auth_unpack_next(struct iovec *data, struct iovec iovs[], int iov_count,
		auth_opcode_t *op, uint8_t *flags)
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

size_t auth_unpack_field(struct iovec *iov, void *data)
{
	unsigned char clen;
	clen = ((unsigned char *)data++)[0];
	iov->iov_len = clen;
	iov->iov_base = data;
	return (size_t) clen + 1;
}

size_t auth_unpack(authpkt_t *pkt, void *data)
{
	size_t clen = 1;
	clen += auth_unpack_field(&pkt->repl, data + clen);
	clen += auth_unpack_field(&pkt->user, data + clen);
	clen += auth_unpack_field(&pkt->mail, data + clen);
	clen += auth_unpack_field(&pkt->pass, data + clen);
	clen += auth_unpack_field(&pkt->serv, data + clen);
	return clen;
}
