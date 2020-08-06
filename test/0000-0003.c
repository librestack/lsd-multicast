/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/config.h"
#include "../src/server.h"
#include <librecast.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>

void *stopthread(void *arg)
{
	struct timespec t = { 0, 1 };
	nanosleep(&t, &t);
	server_stop();
	pthread_exit(arg);
}

int main()
{
	pthread_t thread;

	test_name("start/stop server");
	config.debug = 1;
	config.loglevel = 127;

	/* create thread to stop server */
	pthread_attr_t attr = {};
	pthread_attr_init(&attr);
	pthread_create(&thread, &attr, stopthread, NULL);

	test_assert(server_start() == 0, "server_start()");

	pthread_join(thread, NULL);

	return fails;
}
