/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "config.h"
#include "log.h"
#include "lex.h"

config_t config = {
	.loglevel = 0,
	.modules = 0,
};

static void config_free_ptr(void *ptr)
{
	free(ptr);
	ptr = NULL;
}

static void config_free_handlers(void) {
	handler_t *h, *p;
	p = config.handlers;
	while (p) {
		config_free_ptr(p->channel);
		config_free_ptr(p->channelhash);
		config_free_ptr(p->key_private);
		config_free_ptr(p->key_public);
		config_free_ptr(p->module);
		config_free_ptr(p->scope);
		h = p;
		p = p->next;
		free(h);
	}
	config.handlers = NULL;
}

void config_free(void)
{
	config_free_ptr(config.cert);
	config_free_ptr(config.configfile);
	config_free_ptr(config.key);
	config_free_ptr(config.modpath);
	config_free_handlers();
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

int config_modules_load(void)
{
	if (!config.modules) return 0;
	config.mods = calloc(config.modules, sizeof(module_t));
	for (module_t *mod = config.mods; mod->name; mod++) {
		DEBUG("loading module '%s'", mod->name);
		mod->ptr = dlopen(mod->name, RTLD_LAZY);
		/* TODO: dlsym() required functions */
	}
	return config.modules;
}

void config_modules_unload(void)
{
	for (module_t *mod = config.mods; mod->name; mod++) {
		dlclose(mod->ptr);
	}
	free(config.mods);
}

int config_parse(void)
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
