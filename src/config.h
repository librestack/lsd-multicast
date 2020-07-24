/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#ifndef _LSDBD_CONFIG_H
#define _LSDBD_CONFIG_H

#include "y.tab.h"

#define CONFIG_LOGLEVEL_MAX 127

typedef struct config_s config_t;
struct config_s {
	int	daemon;
	int	debug;
	int	loglevel;
	char *	configfile;
	char *	key;
	char *	cert;
};
extern config_t config;

void	config_free();
int	config_include(char *configfile);
int	config_parse();

#endif /* _LSDBD_CONFIG_H */
