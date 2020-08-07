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
	struct iovec repl= { .iov_base = "0000-0006" };
	struct iovec user= { .iov_base = "username" };
	struct iovec mail = { .iov_base = "email" };
	struct iovec pass= { .iov_base = "password" };
	struct iovec serv= { .iov_base = "service" };
	size_t len;
	void *ptr;

	errno = 0;
	test_assert(auth_pack(NULL, &repl, &user, &mail, &pass, &serv) == -1, "data required");
	test_assert(errno == EINVAL, "data NULL => EINVAL");

	errno = 0;
	test_assert(auth_pack(&data, &repl, NULL, NULL, &pass, &serv) == -1, "user or mail required");
	test_assert(errno == EINVAL, "user && mail NULL => EINVAL");

	errno = 0;
	test_assert(auth_pack(&data, &repl, &user, NULL, &pass, &serv) > 0, "mail can be null");

	errno = 0;
	test_assert(auth_pack(&data, &repl, NULL, &mail, &pass, &serv) > 0, "user can be null");

	user.iov_len = UCHAR_MAX + 1;
	errno = 0;
	test_assert(auth_pack(&data, NULL, &user, &mail, &pass, &serv) == -1, "username too long");
	test_assert(errno == E2BIG, "username E2BIG");
	user.iov_len = 0;

	repl.iov_len = UCHAR_MAX + 1;
	errno = 0;
	test_assert(auth_pack(&data, &repl, &user, &mail, &pass, &serv) == -1, "replyto too long");
	test_assert(errno == E2BIG, "replyto E2BIG");
	repl.iov_len = 0;

	mail.iov_len = UCHAR_MAX + 1;
	errno = 0;
	test_assert(auth_pack(&data, NULL, &user, &mail, &pass, &serv) == -1, "email too long");
	test_assert(errno == E2BIG, "email E2BIG");
	mail.iov_len = 0;

	pass.iov_len = UCHAR_MAX + 1;
	errno = 0;
	test_assert(auth_pack(&data, NULL, &user, &mail, &pass, &serv) == -1, "password too long");
	test_assert(errno == E2BIG, "password E2BIG");
	pass.iov_len = 0;

	serv.iov_len = UCHAR_MAX + 1;
	errno = 0;
	test_assert(auth_pack(&data, NULL, &user, &mail, &pass, &serv) == -1, "service too long");
	test_assert(errno == E2BIG, "service E2BIG");

	repl.iov_len = strlen(repl.iov_base);
	user.iov_len = strlen(user.iov_base);
	mail.iov_len = strlen(mail.iov_base);
	pass.iov_len = strlen(pass.iov_base);
	serv.iov_len = strlen(serv.iov_base);
	len = repl.iov_len + user.iov_len + mail.iov_len + pass.iov_len + serv.iov_len + 5;
	test_assert(auth_pack(&data, &repl, &user, &mail, &pass, &serv) == len,
			"auth_pack() ok");
	ptr = data.iov_base;
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
