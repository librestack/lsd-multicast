/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include <librecast.h>
#include "config.h"
#include "log.h"
#include "server.h"

lc_ctx_t *lctx;
lc_socket_t *sock;
lc_channel_t *chan;

void server_stop()
{
	DEBUG("Stopping server");
	lc_socket_close(sock);
	lc_ctx_free(lctx);
}

int server_start()
{
	DEBUG("Starting server");
	lctx = lc_ctx_new();
	sock = lc_socket_new(lctx);

	return 0;
}
