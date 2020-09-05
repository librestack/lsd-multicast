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

static void sighandler(int sig)
{
	(void)sig;
	running = 0;
}

void server_stop(void)
{
	DEBUG("Stopping server");
	kill(getpid(), SIGINT);
}

void server_start(void)
{
	struct sigaction sa = { .sa_handler = sighandler };
	lc_ctx_t *lctx;
	lc_socket_t *sock;
	lc_channel_t *chan;
	module_t *mod;

	DEBUG("Starting server");
	if (!config.handlers) {
		INFO("No handlers configured.");
		return;
	}
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);
	lctx = lc_ctx_new();
	if (config_modules_load()) {
		mod = config.mods;
		for (handler_t *h = config.handlers; h; h = h->next) {
			DEBUG("starting handler on channel '%s'", h->channel);
			if (!h->module) continue;
			if (!mod->handle_msg) continue;
			sock = lc_socket_new(lctx);
			chan = lc_channel_new(lctx, h->channel);
			lc_channel_bind(sock, chan);
			lc_channel_join(chan);
			lc_socket_listen(sock, mod->handle_msg, mod->handle_err);
			mod++;
		}
		while (running) pause();
	}
	config_modules_unload();
	lc_ctx_free(lctx);
}
