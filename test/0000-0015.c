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
	test_name("auth user token verification");
	char dbpath[] = "0000-0015.tmp.XXXXXX";
	config_include("./0000-0015.conf");
	auth_init();
	test_assert(lc_db_open(lctx, mkdtemp(dbpath)) == 0, "lc_db_open() - open temp db");

	/* create user, set token */
	struct iovec mail = { .iov_base = "noone@example.com" };
	mail.iov_len = strlen(mail.iov_base);
	char userid[AUTH_HEXLEN];
	auth_user_create(userid, &mail, NULL);

	/* create and set token in testmode */
	test_log("create user token");
	auth_user_token_t token;
	auth_payload_t payload;
	payload.senderkey = (unsigned char *)config.handlers->key_public;
	auth_user_token_new(&token, &payload);
	test_log("set user token");
	auth_user_token_set(userid, &token);

	struct iovec tok = { .iov_base = token.hextoken };
	tok.iov_len = strlen(tok.iov_base);
	struct iovec pass = { .iov_base = "password" };
	pass.iov_len = strlen(pass.iov_base);
	struct iovec user = { .iov_base = userid };
	user.iov_len = strlen(user.iov_base);

	test_log("try to login before token set");
	test_assert(auth_user_pass_verify(&user, &pass) == -1,
			"auth_user_pass_verify() login before token set (-1)");
	test_assert(errno == EACCES,
			"auth_user_pass_verify() login before token set (EACCES)");

	test_log("user returns with token, set password");
	test_assert(auth_user_token_use(&tok, &pass) == 0,
			"auth_user_token_use()");

	test_log("GOOD password");
	test_assert(auth_user_pass_verify(&user, &pass) == 0,
			"auth_user_pass_verify() OK");

	test_log("BAD password");
	struct iovec bad = { .iov_base = "wrong" };
	bad.iov_len = strlen(bad.iov_base);
	test_assert(auth_user_pass_verify(&user, &bad) == -1,
			"auth_user_pass_verify() bad password");

	test_log("GOOD password, BAD userid");
	test_assert(auth_user_pass_verify(&bad, &pass) == -1,
			"auth_user_pass_verify() - GOOD password, BAD user");


	/* TODO: try login (OK) */
	struct iovec captoken = {0};
	struct iovec serv = { .iov_base = "service" };
	serv.iov_len = strlen(serv.iov_base);
	auth_serv_token_get(&captoken, &user, &pass, &serv);

	/* TODO: verify service token (crypto signature, has my pub key, expiry) */

	/* TODO: try invalid login email (EKEYREJECTED) */

	/* TODO: try expired token (EKEYEXPIRED) */

	test_assert(auth_user_create(userid, &mail, NULL) == -1,
			"can't create two users with same email");
	test_assert(errno == EADDRINUSE, "duplicate email (EADDRINUSE)");

	auth_free();
	config_free();
	return fails;
}
