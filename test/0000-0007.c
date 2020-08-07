/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/auth.h"
#include "../src/config.h"
#include <librecast.h>
#include <string.h>
#include <unistd.h>

int main()
{
	test_name("auth_unpack()");
	config.debug = 1;
	config.loglevel = 127;
	authpkt_t pkt;
	struct iovec data;
	struct iovec repl = { .iov_base = "0000-0007" };
	struct iovec user = { .iov_base = "username" };
	struct iovec mail = { .iov_base = "email" };
	struct iovec pass = { .iov_base = "password" };
	struct iovec serv = { .iov_base = "service" };
	size_t len;

	repl.iov_len = strlen(repl.iov_base);
	user.iov_len = strlen(user.iov_base);
	mail.iov_len = strlen(mail.iov_base);
	pass.iov_len = strlen(pass.iov_base);
	serv.iov_len = strlen(serv.iov_base);
	len = repl.iov_len + user.iov_len + mail.iov_len + pass.iov_len + serv.iov_len + 5;
	test_assert(auth_pack(&data, &repl, &user, &mail, &pass, &serv) == len,
			"auth_pack() ok");

	test_assert(auth_unpack(&pkt, (&data)->iov_base, (&data)->iov_len) == len,
			"auth_unpack() ok");

	test_assert(pkt.repl.iov_len == repl.iov_len,
			"repl len: %zu == %zu", pkt.repl.iov_len, repl.iov_len);
	test_expectn(pkt.repl.iov_base, repl.iov_base, repl.iov_len);

	test_assert(pkt.user.iov_len == user.iov_len,
			"user len: %zu == %zu", pkt.user.iov_len, user.iov_len);
	test_expectn(pkt.user.iov_base, user.iov_base, user.iov_len);

	test_assert(pkt.mail.iov_len == mail.iov_len,
			"mail len: %zu == %zu", pkt.mail.iov_len, mail.iov_len);
	test_expectn(pkt.mail.iov_base, mail.iov_base, mail.iov_len);

	test_assert(pkt.pass.iov_len == pass.iov_len,
			"pass len: %zu == %zu", pkt.pass.iov_len, pass.iov_len);
	test_expectn(pkt.pass.iov_base, pass.iov_base, pass.iov_len);

	test_assert(pkt.serv.iov_len == serv.iov_len,
			"serv len: %zu == %zu", pkt.serv.iov_len, serv.iov_len);
	test_expectn(pkt.serv.iov_base, serv.iov_base, serv.iov_len);

	free(data.iov_base);

	return fails;
}
