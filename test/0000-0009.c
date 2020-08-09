/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/auth.h"
#include "../src/config.h"
#include <librecast.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

int main()
{
	test_name("auth_pack_next()");
	config.debug = 1;
	config.loglevel = 127;

	struct iovec data;
	struct iovec repl = { .iov_base = "replyto" };
	struct iovec user = { .iov_base = "uuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu" };
	struct iovec mail = { .iov_base = "email" };
	struct iovec pass = { .iov_base = "password" };
	struct iovec serv = { .iov_base = "service" };
	struct iovec *iovs[] = { &repl, &user, &mail, &pass, &serv };
	const int iov_count = sizeof iovs / sizeof iovs[0];
	size_t len_check;
	uint8_t flags = 0;
	auth_opcode_t op = AUTH_OP_KEY_REP;
	void *ptr;

	flags |= 42;

	errno = 0;
	test_assert(auth_pack_next(NULL, NULL, iov_count, op, flags) == -1, "ensure data != NULL");
	test_assert(errno == EINVAL, "data NULL => EINVAL");

	len_check = 1 + iov_count;
	for (int i = 0; i < iov_count; i++) {
		iovs[i]->iov_len = strlen(iovs[i]->iov_base);
		len_check += iovs[i]->iov_len;
		for (size_t j = UINT8_MAX; j <= iovs[i]->iov_len; j += UINT8_MAX) {
			len_check++; /* extra byte needed for length */
		}
	}
	test_assert(auth_pack_next(&data, iovs, iov_count, op, flags) == len_check,
			"pack some data");

	/* check opcode & flags */
	errno = 0;
	uint8_t flags_check, op_check;
	op_check = ((uint8_t *)data.iov_base)[0];
	flags_check = ((uint8_t *)data.iov_base)[1];
	test_assert(op == op_check, "opcode set 0x%x == 0x%x", op, op_check);
	test_assert(flags == flags_check, "flags set 0x%x == 0x%x", flags, flags_check);

	/* verify packed data */
	ptr = data.iov_base + 2;
	for (int i = 0; i < iov_count; i++) {
		uint64_t n = 0, shift = 0;
		uint8_t b;
		do {
			b = ((uint8_t *)ptr++)[0];
			n |= (b & 0x7f) << shift;
			shift += 7;
		} while (b & 0x80);
		len_check = (size_t)le64toh(n);
		test_assert(iovs[i]->iov_len == len_check,
				"check length, iovs[%i] %zu == %zu", i, iovs[i]->iov_len, len_check);
		test_expectn(iovs[i]->iov_base, ptr, iovs[i]->iov_len); /* check data */
		ptr += iovs[i]->iov_len;
	}
	free(data.iov_base);

	return fails;
}