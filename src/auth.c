#include "auth.h"
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
	data->iov_len = iov_count; /* n char for lengths */
	for (int i = 0; i < iov_count; i++) {
		if (iovs[i]) data->iov_len += iovs[i]->iov_len;
	}
	ptr = data->iov_base = malloc(data->iov_len);
	for (int i = 0; i < iov_count; i++) {
		ptr = auth_pack_field(iovs[i], ptr);
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
	size_t clen;
	clen  = auth_unpack_field(&pkt->repl, data);
	clen += auth_unpack_field(&pkt->user, data + clen);
	clen += auth_unpack_field(&pkt->mail, data + clen);
	clen += auth_unpack_field(&pkt->pass, data + clen);
	clen += auth_unpack_field(&pkt->serv, data + clen);
	return clen;
}
