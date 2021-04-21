/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include <stdlib.h>
#include "config.h"
#include "opts.h"
#include "lsdbd.h"
#include "server.h"

int main(int argc, char *argv[])
{
	if (opts_parse(argc, argv) == -1 || config_parse()) return EXIT_FAILURE;
	server_start();
	config_free();
	return EXIT_SUCCESS;
}
