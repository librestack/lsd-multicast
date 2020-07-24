/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/config.h"

int main()
{
	test_name("config defaults");

	test_assert(!config.debug, "defaults debug false");
	test_assert(config.loglevel == 0, "default loglevel == 0");
	test_assert(config.key == NULL, "config.key default == NULL");

	return fails;
}
