/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "config.h"
#include "lex.h"

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
	config_free_ptr(config.cert);
	config_free_ptr(config.configfile);
	config_free_ptr(config.key);

	handler_t *h;
	handler_t *p = config.handlers;
	while (p) {
		h = p;
		p = p->next;
		free(h);
	}
	config.handlers = NULL;
}

int config_include(char *configfile)
{
	FILE *fd;
	fprintf(stderr, "importing config '%s'\n", configfile);
	if ((fd = fopen(configfile, "r")) == NULL) {
		perror(__func__);
		return -1;
	}
	yyin = fd;
	yypush_buffer_state(yy_create_buffer(yyin, YY_BUF_SIZE));
	while (yyparse());
	yylex_destroy();
	fclose(fd);
	return 0;
}

int config_parse()
{
	if (!isatty(0)) {
		while (yyparse());
		yylex_destroy();
	}
	if (config.configfile) {
		config_include(config.configfile);
	}
	return 0;
}
