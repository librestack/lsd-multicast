/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/config.h"
#include "../modules/auth.h"
#include <librecast.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

int main()
{
	test_name("auth_valid_email()");
	config.debug = 1;
	config.loglevel = 127;

	struct iovec mail_valid = { .iov_base = "email@example.com" };
	mail_valid.iov_len = strlen(mail_valid.iov_base);
	struct iovec mail_no_at = { .iov_base = "emailexample.com" };
	mail_no_at.iov_len = strlen(mail_no_at.iov_base);
	struct iovec mail_too_short = { .iov_base = "o@" };
	mail_too_short.iov_len = strlen(mail_too_short.iov_base);
	struct iovec mail_no_local = { .iov_base = "@example.com" };
	mail_no_local.iov_len = strlen(mail_no_local.iov_base);
	struct iovec mail_no_domain = { .iov_base = "example@" };
	mail_no_domain.iov_len = strlen(mail_no_domain.iov_base);

	test_assert(auth_valid_email(mail_valid.iov_base, mail_valid.iov_len),
			"valid email");
	test_assert(!auth_valid_email(mail_no_at.iov_base, mail_no_at.iov_len),
			"invalid email - missing '@'");
	test_assert(!auth_valid_email(mail_too_short.iov_base, mail_too_short.iov_len),
			"invalid email - too short (at least 3 chars eg. a@b)");
	test_assert(!auth_valid_email(mail_no_local.iov_base, mail_no_local.iov_len),
			"invalid email - no local part");
	test_assert(!auth_valid_email(mail_no_domain.iov_base, mail_no_domain.iov_len),
			"invalid email - no domain part");

	return fails;
}
