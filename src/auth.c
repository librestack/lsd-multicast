#include "auth.h"
#include <stdlib.h>
#include <string.h>

ssize_t auth_pack(struct iovec *data, struct iovec *repl,
		  struct iovec *user, struct iovec *mail,
		  struct iovec *pass, struct iovec *serv)
{
	void * ptr;
	if (!data) {
		errno = EINVAL;
		return -1;
	}
	if ((!user) && (!mail)) { /* username or email required */
		errno = EINVAL;
		return -1;
	}
	if ((repl && repl->iov_len > UCHAR_MAX) || (user && user->iov_len > UCHAR_MAX)
	 || (mail && mail->iov_len > UCHAR_MAX) || (pass && pass->iov_len > UCHAR_MAX)
	 || (serv && serv->iov_len > UCHAR_MAX))
	{
		errno = E2BIG;
		return -1;
	}
	data->iov_len = 5; /* 5 x char for lengths */
	if (repl) data->iov_len += repl->iov_len;
	if (user) data->iov_len += user->iov_len;
	if (mail) data->iov_len += mail->iov_len;
	if (pass) data->iov_len += pass->iov_len;
	if (serv) data->iov_len += serv->iov_len;
	data->iov_base = malloc(data->iov_len);
	ptr = data->iov_base;
	if (!repl)
		memset(ptr++, 0, 1);
	else {
		memcpy(ptr++, &repl->iov_len, 1);
		memcpy(ptr, repl->iov_base, repl->iov_len);
		ptr += repl->iov_len;
	}
	if (!user)
		memset(ptr++, 0, 1);
	else {
		memcpy(ptr++, &user->iov_len, 1);
		memcpy(ptr, user->iov_base, user->iov_len);
		ptr += user->iov_len;
	}
	if (!mail)
		memset(ptr++, 0, 1);
	else {
		memcpy(ptr++, &mail->iov_len, 1);
		memcpy(ptr, mail->iov_base, mail->iov_len);
		ptr += mail->iov_len;
	}
	if (!pass)
		memset(ptr++, 0, 1);
	else {
		memcpy(ptr++, &pass->iov_len, 1);
		memcpy(ptr, pass->iov_base, pass->iov_len);
		ptr += pass->iov_len;
	}
	if (!serv)
		memset(ptr++, 0, 1);
	else {
		memcpy(ptr++, &serv->iov_len, 1);
		memcpy(ptr, serv->iov_base, serv->iov_len);
	}
	return data->iov_len;
}

size_t auth_unpack_field(struct iovec *iov, void *data, size_t len)
{
	unsigned char clen;
	clen = ((unsigned char *)data++)[0];
	iov->iov_len = clen;
	iov->iov_base = data;
	return (size_t) clen + 1;
}

size_t auth_unpack(authpkt_t *pkt, void *data, size_t len)
{
	size_t clen;
	clen  = auth_unpack_field(&pkt->repl, data, len);
	clen += auth_unpack_field(&pkt->user, data + clen, len - clen);
	clen += auth_unpack_field(&pkt->mail, data + clen, len - clen);
	clen += auth_unpack_field(&pkt->pass, data + clen, len - clen);
	clen += auth_unpack_field(&pkt->serv, data + clen, len - clen);
	return clen;
}
