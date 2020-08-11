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
	struct timespec ts = { 0, 1 };
	nanosleep(&ts, NULL);
	server_stop();
	pthread_exit(arg);
}

int main()
{
	test_name("start/stop server");
	config_include("./0000-0003.conf");

	/* create thread to stop server */
	pthread_t thread;
	pthread_attr_t attr = {};
	pthread_attr_init(&attr);
	pthread_create(&thread, &attr, testthread, NULL);

	test_assert(server_start() == 0, "server_start()");

	pthread_join(thread, NULL);
	config_free();

	return fails;
}
