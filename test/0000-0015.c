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
	auth_user_token_t token;
	auth_payload_t payload;
	payload.senderkey = (unsigned char *)config.handlers->key_public;
	auth_user_token_new(&token, &payload);
	auth_user_token_set(userid, &token);

	/* TODO: try login before using token (EACCES) */

	/* user returns with token, set password */
	struct iovec tok = { .iov_base = token.hextoken };
	tok.iov_len = strlen(tok.iov_base);
	struct iovec pass = { .iov_base = "password" };
	pass.iov_len = strlen(pass.iov_base);
	test_assert(auth_user_token_use(&tok, &pass) == 0, "auth_user_token_use()");

	/* TODO: try login (OK) */

	/* TODO: try login with wrong password (EACCES) */

	/* TODO: try invalid login email (EKEYREJECTED) */

	/* TODO: try expired token (EKEYEXPIRED) */

	/* TODO: create user with same mail address (EADDRINUSE) */

	auth_free();
	config_free();
	return fails;
}
