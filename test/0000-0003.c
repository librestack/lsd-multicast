/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/config.h"
#include "../src/server.h"
#include <librecast.h>
#include <time.h>
#include <unistd.h>

int main()
{
	struct timespec t = { 0, 0 };

	test_name("start/stop server");
	config.debug = 1;
	config.loglevel = 127;

	test_assert(server_start() == 0, "server_start()");
	nanosleep(&t, &t); /* yield */
	server_stop();

	return fails;
}
