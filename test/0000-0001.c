/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/opts.h"

int main()
{
	test_name("parse commandline options");

	{
		char *argv[] = { "lsdbd", "--debug" };
		opts_parse(2, argv);
		test_assert(config.debug, "debug true");
		test_assert(config.loglevel == CONFIG_LOGLEVEL_MAX, "loglevel set to max");
	}

	{
		char *argv[] = { "lsdbd", "garbage" };
		test_assert(opts_parse(2, argv) == -1, "opts_parse() returns -1 for unknown opts");
	}

	return fails;
}
