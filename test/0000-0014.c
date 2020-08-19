/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../modules/auth.h"
#include "../src/config.h"
#include <librecast.h>

int main()
{
	test_name("auth_user_create()");
	char dbpath[] = "0000-0014.tmp.XXXXXX";
	config_include("./0000-0014.conf");
	auth_init();
	test_assert(lc_db_open(lctx, mkdtemp(dbpath)) == 0, "lc_db_open() - open temp db");

	struct iovec mail = { .iov_base = "mail@example.com" };
	mail.iov_len = strlen(mail.iov_base);
	struct iovec mail_invalid = { .iov_base = "@example.com" };
	mail_invalid.iov_len = strlen(mail_invalid.iov_base);
	struct iovec pass = { .iov_base = "password" };
	pass.iov_len = strlen(pass.iov_base);
	struct iovec nopass = { .iov_base = "", .iov_len = 0 };

	char userid[AUTH_HEXLEN];
	test_assert(auth_user_create(userid, &mail, &pass) == 0,
			"auth_user_create()");

	test_assert(auth_user_create(NULL, &mail_invalid, &pass) == -1,
			"auth_user_create() - invalid email");

	test_assert(auth_user_create(NULL, &mail, &nopass) == -1,
			"auth_user_create() - no password");

	/* try to fetch invalid mail address */
	struct iovec u = {0};
	test_assert(auth_user_bymail(&mail_invalid, &u) == -1,
			"auth_mail_bymail() - user not found");
	test_assert(errno == LC_ERROR_DB_KEYNOTFOUND,
			"auth_mail_bymail() not found - LC_ERROR_DB_KEYNOTFOUND");
	test_assert(auth_user_bymail(&mail, &u) == 0,
			"auth_mail_bymail() - user found");
	test_expectiov(&mail, &u);

	auth_free();

	config_free();
	return fails;
}
