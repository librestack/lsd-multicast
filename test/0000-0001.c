/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/opts.h"

int main()
{
	test_name("parse commandline options");
	config_t saveconf = config;
	{
		char *argv[] = { "lsdbd", "garbage" };
		test_assert(opts_parse(2, argv) == -1, "opts_parse() returns -1 for unknown opts");
		config = saveconf;
	}
	{
		char *argv[] = { "lsdbd", "--debug" };
		opts_parse(2, argv);
		test_assert(config.debug, "debug true");
		test_assert(config.loglevel == CONFIG_LOGLEVEL_MAX, "loglevel set to max");
		config = saveconf;
	}
	{
		char *argv[] = { "lsdbd", "-q" };
		config.loglevel = 1;
		opts_parse(2, argv);
		test_assert(config.loglevel == 0, "--q sets loglevel");
		config = saveconf;
	}
	{
		char *argv[] = { "lsdbd", "--quiet" };
		config.loglevel = 1;
		opts_parse(2, argv);
		test_assert(config.loglevel == 0, "--quiet sets loglevel");
		config = saveconf;
	}
	{
		char *argv[] = { "lsdbd", "-v" };
		opts_parse(2, argv);
		test_assert(config.loglevel == CONFIG_LOGLEVEL_MAX, "-v sets loglevel");
		config = saveconf;
	}
	{
		char *argv[] = { "lsdbd", "--verbose" };
		opts_parse(2, argv);
		test_assert(config.loglevel == CONFIG_LOGLEVEL_MAX, "--verbose sets loglevel");
		config = saveconf;
	}
	return fails;
}
