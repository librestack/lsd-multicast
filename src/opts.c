/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "opts.h"

int opts_parse(int argc, char *argv[])
{
	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--debug")) {
			config.debug = 1;
			config.loglevel = CONFIG_LOGLEVEL_MAX;
		}
		else if (!strcmp(argv[i], "-q") || !strcmp(argv[i], "--quiet")) {
			config.loglevel = 0;
		}
		else if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose")) {
			config.loglevel = CONFIG_LOGLEVEL_MAX;
		}
		else {
			return -1;
		}
	}
	return 0;
}
