/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include <librecast.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"
#include "opts.h"
#include "lsdbd.h"

int main(int argc, char *argv[])
{
	opts_parse(argc, argv);
	config_parse();
	config_free();
	return 0;
}

