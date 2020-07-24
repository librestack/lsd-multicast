/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#ifndef _LSDBD_CONFIG_H
#define _LSDBD_CONFIG_H

#include "y.tab.h"

typedef struct config_s config_t;
struct config_s {
	int	loglevel;
	char *	key;
};
extern config_t config;

void	config_free();
int	config_parse();
void	yylex_destroy();

#endif /* _LSDBD_CONFIG_H */
