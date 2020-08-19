/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../modules/auth.h"
#include "../src/config.h"
#include <librecast.h>
#include <time.h>
#include <unistd.h>

int main()
{
	test_name("auth service capability tokens");
	char dbpath[] = "0000-0016.tmp.XXXXXX";
	config_include("./0000-0016.conf");
	auth_init();
	test_assert(lc_db_open(lctx, mkdtemp(dbpath)) == 0, "lc_db_open() - open temp db");

	struct iovec cap_sig = {0}; /* signed token */
	struct iovec cap_tok = {0}; /* decrypted capabilities */
	struct iovec serv = { .iov_base = "service" };
	serv.iov_len = strlen(serv.iov_base);
	test_assert(auth_serv_token_new(&cap_sig, &serv) == 0,
			"auth_serv_token_new()");

	/* verify signature of cap token */
	unsigned long long cap_len;
	unsigned char pk[crypto_sign_PUBLICKEYBYTES];
	sodium_hex2bin(pk,
			crypto_sign_PUBLICKEYBYTES,
			config.handlers->key_public,
			crypto_sign_PUBLICKEYBYTES * 2,
			NULL,
			0,
			NULL);
	test_assert(crypto_sign_open(cap_tok.iov_base, &cap_len,
		cap_sig.iov_base, cap_sig.iov_len, pk) == 0,
			"verified cap signature");

	/* TODO: check senderkey */
	/* TODO: check service */
	/* TODO: check flags */

	auth_free();
	config_free();
	return fails;
}
