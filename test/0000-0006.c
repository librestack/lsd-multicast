/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/auth.h"
#include "../src/config.h"
#include <librecast.h>
#include <string.h>
#include <unistd.h>

int main()
{
	test_name("auth_pack()");
	config.debug = 1;
	config.loglevel = 127;
	struct iovec data;
	struct iovec repl = { .iov_base = "0000-0006" };
	struct iovec user = { .iov_base = "username" };
	struct iovec mail = { .iov_base = "email" };
	struct iovec pass = { .iov_base = "password" };
	struct iovec serv = { .iov_base = "service" };
	struct iovec *iovs[] = { &repl, &user, &mail, &pass, &serv };
	const int iov_count = sizeof iovs / sizeof iovs[0];
	size_t len;
	void *ptr;

	errno = 0;
	test_assert(auth_pack(NULL, iovs, iov_count) == -1, "data required");
	test_assert(errno == EINVAL, "data NULL => EINVAL");

	errno = 0;
	iovs[AUTH_MAIL] = iovs[AUTH_USER] = NULL;
	test_assert(auth_pack(&data, iovs, iov_count) == -1, "user or mail required");
	test_assert(errno == EINVAL, "user && mail NULL => EINVAL");

	errno = 0;
	iovs[AUTH_USER] = NULL; iovs[AUTH_MAIL] = &mail;
	test_assert(auth_pack(&data, iovs, iov_count) > 0, "user can be null");

	errno = 0;
	iovs[AUTH_USER] = &user; iovs[AUTH_MAIL] = NULL;
	test_assert(auth_pack(&data, iovs, iov_count) > 0, "mail can be null");
	iovs[AUTH_MAIL] = &mail;

	for (int i = 0; i < iov_count; i++) {
		iovs[i]->iov_len = UCHAR_MAX + 1;		/* set length too long */
		errno = 0;
		test_assert(auth_pack(&data, iovs, iov_count) == -1, "field too long");
		test_assert(errno == E2BIG, "errno == E2BIG");
		iovs[i]->iov_len = strlen(iovs[i]->iov_base);	/* reset to correct length */
	}

	len = repl.iov_len + user.iov_len + mail.iov_len + pass.iov_len + serv.iov_len + iov_count + 1;
	test_assert(auth_pack(&data, iovs, iov_count) == len, "auth_pack() ok");

	ptr = data.iov_base + 1;
	test_assert(!memcmp(ptr++, &repl.iov_len, 1), "replyto length set");
	test_assert(!memcmp(ptr, (&repl)->iov_base, repl.iov_len), "replyto data set");
	ptr += repl.iov_len;

	test_assert(!memcmp(ptr++, &user.iov_len, 1), "user length set");
	test_assert(!memcmp(ptr, (&user)->iov_base, user.iov_len), "user data set");
	ptr += user.iov_len;

	test_assert(!memcmp(ptr++, &mail.iov_len, 1), "mail length set");
	test_assert(!memcmp(ptr, (&mail)->iov_base, mail.iov_len), "mail data set");
	ptr += mail.iov_len;

	test_assert(!memcmp(ptr++, &pass.iov_len, 1), "pass length set");
	test_assert(!memcmp(ptr, (&pass)->iov_base, pass.iov_len), "pass data set");
	ptr += pass.iov_len;

	test_assert(!memcmp(ptr++, &serv.iov_len, 1), "serv length set");
	test_assert(!memcmp(ptr, (&serv)->iov_base, serv.iov_len), "serv data set");
	ptr += serv.iov_len;

	free(data.iov_base);

	return fails;
}
