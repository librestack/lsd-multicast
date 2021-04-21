/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/opts.h"

void config_restore(config_t oldconfig)
{
	config_free();
	config = oldconfig;
}

int main()
{
	test_name("parse commandline options");
	config_t saveconf = config;
	{
		char *argv[] = { "lsdbd", "garbage" };
		test_assert(opts_parse(2, argv) == -1, "opts_parse() returns -1 for unknown opts");
	}
	{
		char *argv[] = { "lsdbd", "--config" };
		opts_parse(2, argv);
		test_assert(opts_parse(2, argv) == -1, "--config requires filename");
	}
	{
		char configfile[] = "/path/to/file.conf";
		char *argv[] = { "lsdbd", "-c", configfile };
		test_assert(config.configfile == NULL, "config.configfile defaults to NULL");
		opts_parse(3, argv);
		test_strcmp(configfile, config.configfile, "-c => config file set");
		config_restore(saveconf);
	}
	{
		char configfile[] = "/path/to/file.conf";
		char *argv[] = { "lsdbd", "--config", configfile };
		test_assert(config.configfile == NULL, "config.configfile defaults to NULL");
		opts_parse(3, argv);
		test_strcmp(configfile, config.configfile, "--config file set");
		config_restore(saveconf);
	}
	{
		char *argv[] = { "lsdbd", "--debug" };
		opts_parse(2, argv);
		test_assert(config.debug, "debug true");
		test_assert(config.loglevel == CONFIG_LOGLEVEL_MAX, "loglevel set to max");
		config_restore(saveconf);
	}
	{
		char *argv[] = { "lsdbd", "-q" };
		config.loglevel = 1;
		opts_parse(2, argv);
		test_assert(config.loglevel == 0, "--q sets loglevel");
		config_restore(saveconf);
	}
	{
		char *argv[] = { "lsdbd", "--quiet" };
		config.loglevel = 1;
		opts_parse(2, argv);
		test_assert(config.loglevel == 0, "--quiet sets loglevel");
		config_restore(saveconf);
	}
	{
		char *argv[] = { "lsdbd", "-v" };
		opts_parse(2, argv);
		test_assert(config.loglevel == CONFIG_LOGLEVEL_MAX, "-v sets loglevel");
		config_restore(saveconf);
	}
	{
		char *argv[] = { "lsdbd", "--verbose" };
		opts_parse(2, argv);
		test_assert(config.loglevel == CONFIG_LOGLEVEL_MAX, "--verbose sets loglevel");
		config_restore(saveconf);
	}
	return fails;
}
