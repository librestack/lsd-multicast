/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../modules/auth.h"
#include "../src/config.h"
#include <unistd.h>

int main()
{
	test_name("auth_create_user_token()");
	config_include("./0000-0011.conf");

	unsigned char token[crypto_box_PUBLICKEYBYTES];
	unsigned char seed[randombytes_SEEDBYTES];
	char hextoken[AUTH_HEXLEN];
	auth_user_token_t tok;
	auth_payload_t payload;

	payload.senderkey = (unsigned char *)config.handlers->key_public;
	test_assert(auth_create_user_token(&tok, &payload) == 0,
			"auth_create_user_token()");
	memcpy(seed, config.handlers->key_public, randombytes_SEEDBYTES);
	randombytes_buf_deterministic(token, sizeof token, seed);
	sodium_bin2hex(hextoken, sizeof hextoken, token, sizeof token);
	test_log("test runner token  : %s", hextoken);
	test_log("auth handler token : %s", hextoken);
	test_expect(hextoken, tok.hextoken);

	/* TODO: check 14min < expiry < 15min */

	config_free();
	return fails;
}
