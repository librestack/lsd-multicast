/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../modules/auth.h"
#include "../src/config.h"
#include "../src/wire.h"
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

	/* create new cap token */
	struct iovec cap_sig = {0}; /* signed token */
	struct iovec clientkey = { .iov_base = "wibble" }; /* TODO */
	clientkey.iov_len = strlen(clientkey.iov_base);
	struct iovec serv = { .iov_base = "service" };
	serv.iov_len = strlen(serv.iov_base);
	test_assert(auth_serv_token_new(&cap_sig, &clientkey, &serv) == 0,
			"auth_serv_token_new()");
	test_log("cap_sig.iov_len = %zu", cap_sig.iov_len);

	test_assert(cap_sig.iov_len > 0, "cap token check length");

	/* verify signature of cap token */
	unsigned char *cap = malloc(cap_sig.iov_len - crypto_sign_BYTES);
	unsigned long long cap_len;
	unsigned char pk[crypto_sign_PUBLICKEYBYTES];

	auth_key_sign_pk_bin(pk, config.handlers->key_public);

	test_assert(crypto_sign_open(cap, &cap_len,
		cap_sig.iov_base, cap_sig.iov_len, pk) == 0,
			"verified cap signature");

	/* unpack the token and check it */
	struct iovec iovs[2] = {0};
	const int iov_count = sizeof iovs / sizeof iovs[0];
	uint64_t expires;
	struct iovec pre[1] = {0};
	const int pre_count = sizeof pre / sizeof pre[0];
	struct iovec data = { .iov_base = cap, .iov_len = cap_len };
	pre[0].iov_len = sizeof expires;
	pre[0].iov_base = &expires;
	wire_unpack_pre(&data, iovs, iov_count, pre, pre_count);

	test_log("expires: %u", expires);

	/* t-5s < expires <= t */
	/* FIXME: limit from config */
	expires = be64toh(expires);
	test_assert(expires > time(NULL) + 60 * 60 * 8 - 5, "check expires");
	test_assert(expires <= time(NULL) + 60 * 60 * 8, "check expires");

	test_expectiov(&clientkey, &iovs[0]);
	test_expectiov(&serv, &iovs[1]);

	/* TODO: check senderkey */
	/* TODO: check service */
	/* TODO: check flags */

	free(cap);
	free(cap_sig.iov_base);
	auth_free();
	config_free();
	return fails;
}
