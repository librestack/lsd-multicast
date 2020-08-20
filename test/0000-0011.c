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
	test_name("auth_user_token_new()");
	char dbpath[] = "0000-0011.tmp.XXXXXX";
	config_include("./0000-0011.conf");
	auth_init();
	test_assert(lc_db_open(lctx, mkdtemp(dbpath)) == 0, "lc_db_open() - open temp db");

	unsigned char token[crypto_box_PUBLICKEYBYTES];
	unsigned char seed[randombytes_SEEDBYTES];
	char hextoken[AUTH_HEXLEN];
	auth_user_token_t tok = {0};
	auth_payload_t payload = {0};

	payload.senderkey.iov_base = config.handlers->key_public;
	payload.senderkey.iov_len = strlen(config.handlers->key_public);
	test_assert(auth_user_token_new(&tok, &payload) == 0,
			"auth_user_token_new()");
	memcpy(seed, config.handlers->key_public, randombytes_SEEDBYTES);
	randombytes_buf_deterministic(token, sizeof token, seed);
	sodium_bin2hex(hextoken, sizeof hextoken, token, sizeof token);
	test_log("test runner token  : %s", hextoken);
	test_log("auth handler token : %s", hextoken);
	test_expect(hextoken, tok.hextoken);

	/* check 14min < expiry < 15min */
	time_t now = time(NULL);
	time_t expires = be64toh(tok.expires);
	test_assert(expires > now + 60 * 14, "expiry > 14min");
	test_assert(expires <= now + 60 * 15, "expiry <= 15min");
	test_log("now; %llu", now);
	test_log("exp; %llu", expires);
	test_log("dif; %llu", expires - now);

	test_assert(auth_user_token_valid(&tok), "auth_user_token_valid()");

	/* make up a userid */
	char userid[AUTH_HEXLEN];
	unsigned char userid_bytes[crypto_box_PUBLICKEYBYTES];
	randombytes_buf(userid_bytes, sizeof userid_bytes);
	sodium_bin2hex(userid, AUTH_HEXLEN, userid_bytes, sizeof userid_bytes);

	test_assert(auth_user_token_set(userid, &tok) == 0,
			"auth_user_token_set()");

	struct iovec badtoken = { .iov_base = "badtoken" };
	badtoken.iov_len = strlen(badtoken.iov_base);
	struct iovec usertoken = { .iov_base = tok.hextoken };
	usertoken.iov_len = strlen(usertoken.iov_base);
	struct iovec pass = { .iov_base = "correcthorsebatterystaple" };
	pass.iov_len = strlen(pass.iov_base);
	test_assert(auth_user_token_use(&badtoken, &pass) == -1,
			"auth_user_token_use() - bad token");
	test_assert(auth_user_token_use(&usertoken, &pass) == 0,
			"auth_user_token_use() - set password");
	/* TODO: test_assert(auth_user_token_use(&usertoken, &pass) == -1,
			"auth_user_token_use() - use same token twice"); */
	/* TODO: expired token */

	auth_free();
	config_free();
	return fails;
}
