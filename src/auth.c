#include "auth.h"

ssize_t auth_pack(struct iovec *username, struct iovec *email,
		  struct iovec *password, struct iovec *service)
{
	ssize_t ret = 0;
	if ((username->iov_len > UCHAR_MAX)
	|| (email->iov_len > UCHAR_MAX)
	|| (password->iov_len > UCHAR_MAX)
	|| (service->iov_len > UCHAR_MAX)) {
		errno = E2BIG;
		return -1;
	}
	return ret;
}
