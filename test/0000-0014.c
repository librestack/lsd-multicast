/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../modules/auth.h"
#include "../src/config.h"

int main()
{
	test_name("auth_user_create()");
	struct iovec user = { .iov_base = "user@example.com" };
	user.iov_len = strlen(user.iov_base);
	struct iovec user_invalid = { .iov_base = "@example.com" };
	user_invalid.iov_len = strlen(user_invalid.iov_base);
	struct iovec pass = { .iov_base = "password" };
	pass.iov_len = strlen(pass.iov_base);
	struct iovec nopass = { .iov_base = "", .iov_len = 0 };

	test_assert(auth_user_create(&user, &pass) == 0, "auth_user_create()");

	test_assert(auth_user_create(&user_invalid, &pass) == -1,
			"auth_user_create() - invalid email");

	test_assert(auth_user_create(&user, &nopass) == -1,
			"auth_user_create() - no password");

	return fails;
}
