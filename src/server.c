/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include <librecast.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "config.h"
#include "log.h"
#include "server.h"

lc_ctx_t *lctx;
lc_socket_t *sock;
lc_channel_t *chan;

void server_message_recv(lc_message_t *msg)
{
	DEBUG("server received message");
}

void server_stop()
{
	DEBUG("Stopping server");
	lc_socket_listen_cancel(sock);
	lc_channel_free(chan);
	lc_socket_close(sock);
	lc_ctx_free(lctx);
}

int server_start()
{
	DEBUG("Starting server");
	char dbpath[] = "/tmp/lsdbd.tmp.XXXXXX";
	lctx = lc_ctx_new();
	lc_db_open(lctx, mkdtemp(dbpath));
	sock = lc_socket_new(lctx);
	chan = lc_channel_new(lctx, "radio freedom"); // FIXME: channel from config
	lc_channel_bind(sock, chan);
	lc_channel_join(chan);
	lc_socket_listen(sock, server_message_recv, NULL);
	return 0;
}
