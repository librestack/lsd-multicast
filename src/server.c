/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include <errno.h>
#include <librecast.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "auth.h"
#include "config.h"
#include "log.h"
#include "server.h"

static volatile sig_atomic_t running = 1;
lc_ctx_t *lctx;
lc_socket_t *sock;
lc_channel_t *chan;

void sighandler(int sig)
{
	running = 0;
}

void server_reply(lc_message_t *msg) /* FIXME: TEMP */
{
	authpkt_t pkt;
	lc_channel_t *chan_repl;
	lc_message_t msg_repl;

	/* unpack auth packet, reply to reply to channel */
	DEBUG("auth packet received");
	auth_unpack(&pkt, msg->data, msg->len);
	DEBUG("reply channel: '%.*s'", (int)pkt.repl.iov_len, (char *)pkt.repl.iov_base);
	DEBUG("user: '%.*s'", (int)pkt.user.iov_len, (char *)pkt.user.iov_base);
	DEBUG("mail: '%.*s'", (int)pkt.mail.iov_len, (char *)pkt.mail.iov_base);
	DEBUG("pass: '%.*s'", (int)pkt.pass.iov_len, (char *)pkt.pass.iov_base);
	DEBUG("serv: '%.*s'", (int)pkt.serv.iov_len, (char *)pkt.serv.iov_base);

	/* reply to requested reply channel */
	int opt = 1;
	lc_socket_setopt(sock, IPV6_MULTICAST_LOOP, &opt, sizeof(opt)); /* FIXME */
	char *repl = strndup((char *)pkt.repl.iov_base, pkt.repl.iov_len);
	chan_repl = lc_channel_new(lctx, repl);
	lc_channel_bind(sock, chan_repl);

	lc_msg_init_data(&msg_repl, pkt.repl.iov_base, pkt.repl.iov_len, NULL, NULL);
	lc_msg_send(chan_repl, &msg_repl);
	free(repl);

	lc_channel_unbind(chan_repl);
	lc_channel_free(chan_repl);
}

void server_stop(void)
{
	DEBUG("Stopping server");
	kill(getpid(), SIGINT);
}

int server_start(void)
{
	DEBUG("Starting server");
	char dbpath[] = "/tmp/lsdbd.tmp.XXXXXX";
	ssize_t byt_recv;
	struct sigaction sa = { .sa_handler = sighandler };

	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);

	lc_message_t msg;
	lctx = lc_ctx_new();
	lc_db_open(lctx, mkdtemp(dbpath));
	sock = lc_socket_new(lctx);
	chan = lc_channel_new(lctx, "auth"); // FIXME: channel from config
	lc_channel_bind(sock, chan);
	lc_channel_join(chan);
	while (running) {
		byt_recv = lc_msg_recv(sock, &msg);
		if (byt_recv == -1 && errno == EINTR) continue;
		//if (byt_recv > 0) running = 0; // TODO: process auth packet
		// TODO: hand packet to processing thread
		server_reply(&msg);
		lc_msg_free(&msg);
	}
	lc_channel_free(chan);
	lc_socket_close(sock);
	lc_ctx_free(lctx);

	return 0;
}
