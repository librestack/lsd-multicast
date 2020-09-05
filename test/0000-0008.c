/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/config.h"
#include "../src/server.h"
#include <librecast.h>
#include <pthread.h>
#include <unistd.h>

void *testthread(void *arg)
{
	lc_ctx_t *lctx;
	lc_socket_t *sock, *sock_repl;
	lc_channel_t *chan, *chan_repl;
	lc_message_t msg, msg_repl;
	char data[] = "hello";
	int opt = 1;

	lctx = lc_ctx_new();
	sock = lc_socket_new(lctx);
	sock_repl = lc_socket_new(lctx);
	lc_socket_setopt(sock, IPV6_MULTICAST_LOOP, &opt, sizeof(opt));
	chan = lc_channel_new(lctx, config.handlers->channel);
	chan_repl = lc_channel_new(lctx, "repl");
	lc_channel_bind(sock, chan);
	lc_channel_bind(sock_repl, chan_repl);
	lc_channel_join(chan_repl);

	lc_msg_init_data(&msg, &data, strlen(data), NULL, NULL);
	test_sleep(0, 999999); /* give server a chance to be ready */
	lc_msg_send(chan, &msg);
	test_sleep(0, 999999); /* give server a chance to be ready */
	lc_msg_recv(sock_repl, &msg_repl);
	test_expectn(data, msg_repl.data, msg_repl.len);
	lc_msg_free(&msg_repl);

	lc_ctx_free(lctx);
	server_stop();
	pthread_exit(arg);
}

int main()
{
	return test_skip("echo handler test");
	config_include("./0000-0008.conf");

	/* create thread to run tests */
	pthread_t thread;
	pthread_attr_t attr = {0};
	pthread_attr_init(&attr);
	pthread_create(&thread, &attr, testthread, NULL);

	/* start server */
	server_start();

	/* wait for test thread to complete */
	pthread_join(thread, NULL);
	config_free();

	return fails;
}
