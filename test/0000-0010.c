/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../modules/auth.h"
#include "../src/config.h"
#include "../src/server.h"
#include "../src/wire.h"
#include <assert.h>
#include <librecast.h>
#include <signal.h>
#include <sodium.h>
#include <unistd.h>

int main()
{
	unsigned char userid_bytes[crypto_box_PUBLICKEYBYTES];
	const size_t hexlen = crypto_box_PUBLICKEYBYTES * 2 + 1;
	char userid[hexlen];
	void *vptr = NULL;
	size_t vlen;

	test_name("auth_field_set() / hash_field()");
	char dbpath[] = "0000-0010.tmp.XXXXXX";
	config_include("./0000-0010.conf");
	auth_init();
	test_assert(lc_db_open(lctx, mkdtemp(dbpath)) == 0, "lc_db_open() - open temp db");

	/* use auth_field_set() to hash random user id with field "pkey" and write */
	randombytes_buf(userid_bytes, sizeof userid_bytes);
	sodium_bin2hex(userid, hexlen, userid_bytes, sizeof userid_bytes);
	test_log("userid created: %s", userid);
	auth_field_set(userid, hexlen, "pkey", config.handlers->key_public, crypto_box_PUBLICKEYBYTES);

	test_assert(auth_field_get(userid, hexlen, "pkey", &vptr, &vlen) == 0,
			"auth_field_get() userid.pkey");
	test_expectn(config.handlers->key_public, (char *)vptr, vlen);
	free(vptr);

	char mail[] = "noone@example.com";
	size_t maillen = strlen(mail);
	auth_field_set(userid, hexlen, "mail", mail, maillen);

	test_assert(auth_field_get(userid, hexlen, "mail", &vptr, &vlen) == 0,
			"auth_field_get() userid.pkey");
	test_expectn(mail, (char *)vptr, vlen);
	free(vptr);

	/* now, lets use a more civilized function */
	test_assert(auth_field_get(userid, hexlen, "mail", &vptr, &vlen) == 0,
			"auth_field_get() userid.mail");
	test_assert(vlen == maillen, "auth_field_get() mail length matches");
	test_expectn(mail, vptr, vlen);
	free(vptr);

	/* index email -> userid */
	auth_field_set(mail, maillen, "user", userid, AUTH_HEXLEN);
	test_assert(auth_field_get(mail, maillen, "user", &vptr, &vlen) == 0,
			"auth_field_get() mail.user");
	test_assert(vlen == hexlen, "auth_field_get() user length matches");
	test_expectn(userid, vptr, vlen);
	free(vptr);

	struct iovec res = {0};
	test_assert(auth_field_getv(mail, maillen, "user", &res) == 0,
			"auth_field_getv()");
	test_expectn(userid, res.iov_base, strlen(userid));
	free(res.iov_base);

	auth_free();
	config_free();
	return fails;
}
