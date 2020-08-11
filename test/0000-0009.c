/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/config.h"
#include "../src/server.h"
#include <assert.h>
#include <librecast.h>
#include <signal.h>
#include <unistd.h>

void runtests(pid_t pid)
{
	lc_ctx_t *lctx;
	lc_socket_t *sock;
	lc_channel_t *chan;
	lc_message_t msg;
	char data[] = "hello";
	int opt = 1;

	lctx = lc_ctx_new();
	sock = lc_socket_new(lctx);
	lc_socket_setopt(sock, IPV6_MULTICAST_LOOP, &opt, sizeof(opt));
	chan = lc_channel_new(lctx, config.handlers->channel);
	lc_channel_bind(sock, chan);

	lc_msg_init_data(&msg, &data, strlen(data), NULL, NULL);
	test_sleep(0, 999999); /* give server a chance to be ready */
	lc_msg_send(chan, &msg);
	test_sleep(0, 999999); /* give server a chance to read message */

	lc_ctx_free(lctx);
	kill(pid, SIGINT); /* stop server */
}

int main()
{
	test_name("handler test (forking)");
	config_include("./0000-0008.conf");
	pid_t pid = fork();
	assert (pid != -1);
	if (pid)
		runtests(pid);
	else {
		assert(server_start() == 0);
		close(1); /* prevent server messing up test output */
	}
	config_free();
	return fails;
}
