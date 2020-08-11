/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include <errno.h>
#include <librecast.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "config.h"
#include "log.h"
#include "server.h"
#include "wire.h"

static volatile sig_atomic_t running = 1;

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
	struct sigaction sa = { .sa_handler = sighandler };
	lc_ctx_t *lctx;
	lc_socket_t *sock;
	lc_channel_t *chan;

	if (!config.handlers) {
		INFO("No handlers configured.");
		return 0;
	}
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);
	lctx = lc_ctx_new();
	for (handler_t *h = config.handlers; h; h = h->next) {
		DEBUG("starting handler on channel '%s'", h->channel);
		sock = lc_socket_new(lctx);
		chan = lc_channel_new(lctx, h->channel);
		lc_channel_bind(sock, chan);
		lc_channel_join(chan);
		// TODO: load module
		lc_socket_listen(sock, NULL, NULL); /* FIXME: module callback */
	}
	while (running) pause();
	lc_ctx_free(lctx);
	return 0;
}
