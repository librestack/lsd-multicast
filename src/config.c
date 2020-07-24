/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include <stdlib.h>
#include <unistd.h>
#include "config.h"
#include "y.tab.h"

config_t config = {
	.loglevel = 0,
};

void config_free_ptr(void *ptr)
{
	free(ptr);
	ptr = NULL;
}

void config_free()
{
	config_free_ptr(config.configfile);
	config_free_ptr(config.key);
}

int config_parse()
{
	if (!isatty(0)) {
		while (yyparse());
		yylex_destroy();
	}
	return 0;
}
