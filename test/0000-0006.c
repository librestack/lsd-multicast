/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/auth.h"
#include "../src/config.h"
#include <librecast.h>
#include <unistd.h>

int main()
{
	test_name("auth_pack()");
	config.debug = 1;
	config.loglevel = 127;
	struct iovec username = {};
	struct iovec email = {};
	struct iovec password = {};
	struct iovec service = {};

	username.iov_len = UCHAR_MAX + 1;
	errno = 0;
	test_assert(auth_pack(&username, &email, &password, &service) == -1, "username too long");
	test_assert(errno == E2BIG, "username E2BIG");
	username.iov_len = 0;

	email.iov_len = UCHAR_MAX + 1;
	errno = 0;
	test_assert(auth_pack(&username, &email, &password, &service) == -1, "email too long");
	test_assert(errno == E2BIG, "email E2BIG");
	email.iov_len = 0;

	password.iov_len = UCHAR_MAX + 1;
	errno = 0;
	test_assert(auth_pack(&username, &email, &password, &service) == -1, "password too long");
	test_assert(errno == E2BIG, "password E2BIG");
	password.iov_len = 0;

	service.iov_len = UCHAR_MAX + 1;
	errno = 0;
	test_assert(auth_pack(&username, &email, &password, &service) == -1, "service too long");
	test_assert(errno == E2BIG, "service E2BIG");

	return fails;
}
