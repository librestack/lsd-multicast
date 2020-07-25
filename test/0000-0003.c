/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/config.h"
#include "../src/server.h"
#include <librecast.h>
#include <signal.h>
#include <unistd.h>

int gotmsg = 0;

void callback_recv(lc_message_t *msg)
{
	pid_t pid = getpid();
	fprintf(stdout, "got a msg\n");
	gotmsg = 1;
	kill(pid, SIGUSR1); /* interrupt sleep() */
}

int main()
{
	test_name("ping server");

	config.debug = 1;
	config.loglevel = 127;

	server_start();

	lc_ctx_t *lctx;
	lc_socket_t *sock;
	lc_channel_t *chan;
	lc_message_t msg;
	int opt;

	lctx = lc_ctx_new();
	sock = lc_socket_new(lctx);
	chan = lc_channel_new(lctx, "hello multicast");
	test_assert(lc_channel_bind(sock, chan) == 0, "bind channel to socket");
	test_assert(lc_socket_listen(sock, callback_recv, NULL) == 0, "lc_socket_listen()");

	/* PING */
	opt = LC_OP_PING;
	lc_msg_init(&msg);
	test_assert(lc_msg_set(&msg, LC_ATTR_OPCODE, &opt) == 0, "lc_msg_set()");
	test_assert(lc_msg_send(chan, &msg) == 0, "lc_msg_send()");

	/* wait for PONG */
	sleep(2); /* sleep 2s or until SIGUSR1 */
	test_assert(gotmsg, "ping reply timeout");

	lc_channel_free(chan);
	lc_socket_close(sock);
	lc_ctx_free(lctx);
	server_stop();

	return fails;
}
