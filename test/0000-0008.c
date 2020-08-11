/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/config.h"
#include "../src/server.h"
#include <librecast.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>

void *testthread(void *arg)
{
	struct timespec ts = { 0, 10 };
	nanosleep(&ts, NULL);
	server_stop();
	pthread_exit(arg);
}

int main()
{
	test_name("handlers");
	config_include("./0000-0008.conf");

	/* create thread to run tests */
	pthread_t thread;
	pthread_attr_t attr = {};
	pthread_attr_init(&attr);
	pthread_create(&thread, &attr, testthread, NULL);

	/* start server */
	test_assert(server_start() == 0, "server_start()");

	/* wait for test thread to complete */
	pthread_join(thread, NULL);
	config_free();

	return fails;
}
