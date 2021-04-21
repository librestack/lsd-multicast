/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/config.h"

int main()
{
	test_name("read config");

	test_assert(config_include("./0000-0002.does_not_exist") == -1,
			"config_include returns -1 if file does not exist");
	test_assert(config.key == NULL, "config.key defaults to NULL");
	test_assert(config.modpath == NULL, "config.modpath defaults to NULL");

	config_include("./0000-0002.conf");
	test_assert(config.loglevel == 64, "loglevel set from config file");
	test_assert(config.daemon, "daemon set from config file");
	test_assert(config.debug, "debug set from config file");
	test_strcmp(config.key, "/path/to/key", "config.key set from config file");
	test_strcmp(config.cert, "/path/to/cert", "config.cert set from config file");
	test_strcmp(config.modpath, "/path/to/modules", "config.modpath set from config file");
	config_free();

	return fails;
}
