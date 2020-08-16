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
	char dbpath[] = "0000-0010.tmp.XXXXXX";
	unsigned char userid_bytes[crypto_box_PUBLICKEYBYTES];
	const size_t hexlen = crypto_box_PUBLICKEYBYTES * 2 + 1;
	char userid[hexlen];
	lc_ctx_t *lctx;

	test_name("auth_field_set() / hash_field()");
	config_include("./0000-0010.conf");

	/* use auth_field_set() to hash random user id with field "pkey" and write */
	randombytes_buf(userid_bytes, sizeof userid_bytes);
	sodium_bin2hex(userid, hexlen, userid_bytes, sizeof userid_bytes);
	test_log("userid created: %s", userid);
	lctx = lc_ctx_new();
	test_assert(lc_db_open(lctx, mkdtemp(dbpath)) == 0, "lc_db_open() - open temp db");
	auth_field_set(lctx, userid, hexlen, "pkey", config.handlers->key_public, crypto_box_PUBLICKEYBYTES);

	/* now read it back, using hash_field() to get the key */
	unsigned char hash[crypto_generichash_BYTES];
	void *vptr;
	size_t vlen;
	int ret;
	hash_field(hash, sizeof hash, userid, hexlen, "pkey", 4);
	ret = lc_db_get(lctx, config.handlers->dbname, hash, sizeof hash, &vptr, &vlen);
	if (ret) test_log("lc_db_get() returned %i", ret);
	test_expectn(config.handlers->key_public, (char *)vptr, vlen);
	free(vptr);
	config_free();
	lc_ctx_free(lctx);
	return fails;
}
