/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "echo.h"
#include "../src/log.h"
#include <stdio.h>

void init(void)
{
	TRACE("echo.so %s()", __func__);
	config.loglevel = 127;
	DEBUG("I am the very model of a modern echo module");
}

void finit(void)
{
	TRACE("echo.so %s()", __func__);
}

void handle_msg(lc_message_t *msg)
{
	TRACE("echo.so %s()", __func__);

	lc_ctx_t *lctx = lc_channel_ctx(msg->chan);
	lc_socket_t *sock = lc_channel_socket(msg->chan);
	lc_channel_t *chan_repl = lc_channel_new(lctx, "repl");
	lc_channel_bind(sock, chan_repl);
	lc_msg_send(chan_repl, msg);

	/* TODO:
	 * - decrypt
	 * - call opcode handler
	 * - unpack
	 */

	lc_channel_unbind(chan_repl);

	DEBUG("message says '%.*s'", (int)msg->len, (char *)msg->data);
}

void handle_err(int err)
{
	TRACE("echo.so %s()", __func__);
	DEBUG("handle_err() err=%i", err);
}
