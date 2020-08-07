#include "auth.h"
#include <stdlib.h>
#include <string.h>

ssize_t auth_pack(struct iovec *data, struct iovec *user, struct iovec *mail,
		  struct iovec *pass, struct iovec *serv)
{
	void * ptr;
	if ((user->iov_len > UCHAR_MAX) || (mail->iov_len > UCHAR_MAX)
	 || (pass->iov_len > UCHAR_MAX) || (serv->iov_len > UCHAR_MAX))
	{
		errno = E2BIG;
		return -1;
	}
	data->iov_len = 4 + user->iov_len + mail->iov_len + pass->iov_len + serv->iov_len;
	data->iov_base = malloc(data->iov_len);
	ptr = data->iov_base;
	memcpy(ptr++, &user->iov_len, 1);
	memcpy(ptr, user->iov_base, user->iov_len);
	ptr += user->iov_len;
	memcpy(ptr++, &mail->iov_len, 1);
	memcpy(ptr, mail->iov_base, mail->iov_len);
	ptr += mail->iov_len;
	memcpy(ptr++, &pass->iov_len, 1);
	memcpy(ptr, pass->iov_base, pass->iov_len);
	ptr += pass->iov_len;
	memcpy(ptr++, &serv->iov_len, 1);
	memcpy(ptr, serv->iov_base, serv->iov_len);

	return data->iov_len;
}
