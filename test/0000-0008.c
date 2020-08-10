/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/config.h"
#include "../src/server.h"
#include "../src/wire.h"
#include <librecast.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>

void *testthread(void *arg)
{
	lc_ctx_t *lctx;
	lc_socket_t *sock, *sock_repl;
	lc_channel_t *chan_auth, *chan_repl;
	//lc_message_t msg;
	//ssize_t byt_sent;
	//ssize_t byt_recv;
	struct iovec data, repl, user, mail, pass, serv;
	struct iovec *iovs[] = { &repl, &user, &mail, &pass, &serv };
	const int iov_count = sizeof iovs / sizeof iovs[0];
	char replyto[] = "0000-0008";
	char email[] = "test@live.librecast.net";
	char password[] = "password";
	char service[] = "llive";
	int opt = 1;

	lctx = lc_ctx_new();
	sock = lc_socket_new(lctx);
	sock_repl = lc_socket_new(lctx);
	lc_socket_setopt(sock, IPV6_MULTICAST_LOOP, &opt, sizeof(opt));
	chan_auth = lc_channel_new(lctx, "auth");       /* send to auth channel */
	chan_repl = lc_channel_new(lctx, replyto);	/* reply to us */
	lc_channel_bind(sock, chan_auth);
	lc_channel_bind(sock_repl, chan_repl);
	lc_channel_join(chan_repl);

	/* build auth payload */
	user.iov_len = 0;
	repl.iov_base = replyto;
	repl.iov_len = strlen(replyto);
	mail.iov_base = email;
	mail.iov_len = strlen(email);
	pass.iov_base = password;
	pass.iov_len = strlen(password);
	serv.iov_base = service;
	serv.iov_len = strlen(service);
	int op = 1;
	int flags = 42;
	test_assert(wire_pack(&data, iovs, iov_count, op, flags), "pack request");

	/* TODO: encrypt payload */


	server_stop();

	lc_channel_part(chan_repl);
	lc_channel_free(chan_auth);
	lc_channel_free(chan_repl);
	lc_socket_close(sock);
	lc_ctx_free(lctx);

	pthread_exit(arg);
}

int main()
{
	pthread_t thread;

	test_name("wait for auth packet");
	config.debug = 1;
	config.loglevel = 127;

	/* create thread to run tests */
	pthread_attr_t attr = {};
	pthread_attr_init(&attr);
	pthread_create(&thread, &attr, testthread, NULL);

	/* start server */
	test_assert(server_start() == 0, "server_start()");

	/* wait for test thread to complete */
	pthread_join(thread, NULL);

	return fails;
}
