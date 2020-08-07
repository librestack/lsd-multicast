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
		lc_msg_free(&msg);
	}
	lc_channel_free(chan);
	lc_socket_close(sock);
	lc_ctx_free(lctx);

	return 0;
}
