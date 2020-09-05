/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "config.h"
#include "log.h"
#include "lex.h"
#include "y.tab.h"

config_t config = {
	.loglevel = 0,
	.modules = 0,
};

static void config_free_handlers(void) {
	handler_t *h, *p;
	p = config.handlers;
	while (p) {
		free(p->channel);
		free(p->channelhash);
		free(p->dbname);
		free(p->dbpath);
		free(p->key_private);
		free(p->key_public);
		free(p->module);
		free(p->scope);
		h = p;
		p = p->next;
		free(h);
	}
	config.handlers = NULL;
}

void config_free(void)
{
	free(config.cert);
	free(config.configfile);
	free(config.key);
	free(config.modpath);
	config_free_handlers();
}

int config_include(char *configfile)
{
	FILE *fd;
	fprintf(stderr, "importing config '%s'\n", configfile);
	if ((fd = fopen(configfile, "r")) == NULL) {
		perror(configfile);
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
	TRACE("%s()", __func__);
	module_t *mod;

	if (!config.modules) return 0;
	mod = config.mods = calloc(config.modules, sizeof(module_t));
	for (handler_t *h = config.handlers; h; h = h->next) {
		if (!h->module) continue;
		DEBUG("loading module '%s'", h->module);
		mod->name = h->module;
		mod->handle = dlopen(mod->name, RTLD_LAZY);
		if (mod->handle) {
			DEBUG("%s loaded", mod->name);
		}
		else {
			DEBUG("failed to load %s: '%s'", mod->name, dlerror());
			continue;
		}
		if ((*(void **)(&mod->init) = dlsym(mod->handle, "init"))) mod->init(&config);
		*(void **)(&mod->finit) = dlsym(mod->handle, "finit");
		*(void **)(&mod->handle_msg) = dlsym(mod->handle, "handle_msg");
		*(void **)(&mod->handle_err) = dlsym(mod->handle, "handle_err");
		mod++;
	}
	return config.modules;
}

void config_modules_unload(void)
{
	for (module_t *mod = config.mods; mod && mod->handle; mod++) {
		if (mod->finit) mod->finit();
		dlclose(mod->handle);
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
