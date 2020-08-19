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
	struct iovec u = {0};
	char userid[AUTH_HEXLEN];
	test_assert(auth_user_create(userid, &mail, &pass) == 0,
			"auth_user_create()");
	test_assert(auth_user_create(NULL, &mail_invalid, &pass) == -1,
			"auth_user_create() - invalid email");
	test_assert(auth_user_create(NULL, &mail, &nopass) == -1,
			"auth_user_create() - no password");
	test_assert(auth_user_bymail(&mail_invalid, &u) == -1,
			"auth_mail_bymail() - user not found");
	test_assert(errno == LC_ERROR_DB_KEYNOTFOUND,
			"auth_mail_bymail() not found - LC_ERROR_DB_KEYNOTFOUND");
	free(u.iov_base);
	test_assert(auth_user_bymail(&mail, &u) == 0,
			"auth_mail_bymail() - user found");
	test_expectn(userid, u.iov_base, u.iov_len);
	free(u.iov_base);
	test_assert(auth_field_getv(userid, AUTH_HEXLEN, "mail", &u) == 0,
			"auth_field_getv() - fetch mail for user");
	test_expectiov(&mail, &u);
	free(u.iov_base);
	test_assert(auth_field_getv(userid, AUTH_HEXLEN, "pass", &u) == 0,
			"auth_field_getv() - fetch pass for user");
	test_assert(u.iov_len == crypto_pwhash_STRBYTES, "password length");
	free(u.iov_base);

	memset(userid, 0, sizeof userid);
	test_assert(auth_user_create(userid, &mail, NULL) == 0,
			"auth_user_create() with NULL password");

	auth_free();
	config_free();
	return fails;
}
