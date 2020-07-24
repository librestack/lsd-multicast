/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/config.h"

int main()
{
	test_name("read config");

	test_assert(config_include("./0000-0002.does_not_exist") == -1,
			"config_include returns -1 if file does not exist");

	config_include("./0000-0002.conf");

	return fails;
}
