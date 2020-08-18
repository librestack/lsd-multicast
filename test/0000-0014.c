/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../modules/auth.h"
#include "../src/config.h"
#include <librecast.h>

int main()
{
	test_name("auth_user_create()");
	config_include("./0000-0014.conf");
	struct iovec mail = { .iov_base = "mail@example.com" };
	mail.iov_len = strlen(mail.iov_base);
	struct iovec mail_invalid = { .iov_base = "@example.com" };
	mail_invalid.iov_len = strlen(mail_invalid.iov_base);
	struct iovec pass = { .iov_base = "password" };
	pass.iov_len = strlen(pass.iov_base);
	struct iovec nopass = { .iov_base = "", .iov_len = 0 };

	test_assert(auth_init() == 0, "auth_init()");

	test_assert(auth_user_create(&mail, &pass) == 0,
			"auth_user_create()");

	test_assert(auth_user_create(&mail_invalid, &pass) == -1,
			"auth_user_create() - invalid email");

	test_assert(auth_user_create(&mail, &nopass) == -1,
			"auth_user_create() - no password");

	struct iovec u = {0};
	int ret = auth_user_bymail(&mail, &u);
	test_log("ret=%i", ret);
	test_assert(auth_user_bymail(&mail, &u) == 0,
			"auth_mail_bymail() - user not found");
	test_expectiov(&mail, &u);

	auth_free();

	config_free();
	return fails;
}
