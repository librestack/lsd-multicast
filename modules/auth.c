/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "auth.h"
#include "../src/log.h"
#include <librecast.h>
#include <stdio.h>
#include <stdint.h>

static void auth_op_noop(lc_message_t *msg)
{
	TRACE("auth.so %s()", __func__);
};

static void auth_op_user_add(lc_message_t *msg)
{
	TRACE("auth.so %s()", __func__);

	/* TODO */
};

static void auth_op_user_delete(lc_message_t *msg)
{
	TRACE("auth.so %s()", __func__);
};

static void auth_op_user_lock(lc_message_t *msg)
{
	TRACE("auth.so %s()", __func__);
};

static void auth_op_user_unlock(lc_message_t *msg)
{
	TRACE("auth.so %s()", __func__);
};

static void auth_op_key_add(lc_message_t *msg)
{
	TRACE("auth.so %s()", __func__);
};

static void auth_op_key_delete(lc_message_t *msg)
{
	TRACE("auth.so %s()", __func__);
};

static void auth_op_key_replace(lc_message_t *msg)
{
	TRACE("auth.so %s()", __func__);
};

static void auth_op_auth_service(lc_message_t *msg)
{
	TRACE("auth.so %s()", __func__);
};

void init(void)
{
	TRACE("auth.so %s()", __func__);
	config.loglevel = 127;
	DEBUG("I am the very model of a modern auth module");
}

void finit(void)
{
	TRACE("auth.so %s()", __func__);
}

void handle_msg(lc_message_t *msg)
{
	TRACE("auth.so %s()", __func__);

	/* TODO: read opcode and pass to handler */
	uint8_t opcode = *((uint8_t *)msg->data);
	DEBUG("opcode read: %u", opcode);

	switch (opcode) {
		AUTH_OPCODES(AUTH_OPCODE_FUN)
	default:
		ERROR("Invalid auth opcode received: %u", opcode);
	}

	//lc_ctx_t *lctx = lc_ctx_new();
	lc_ctx_t *lctx = lc_channel_ctx(msg->chan);
	//lc_socket_t *sock = lc_channel_socket(msg->chan);
	lc_socket_t *sock = lc_socket_new(lctx);
	lc_channel_t *chan_repl = lc_channel_new(lctx, "repl");
	DEBUG("auth.so binding socket");
	lc_channel_bind(sock, chan_repl);
	lc_msg_send(chan_repl, msg);

	/* TODO:
	 * - decrypt
	 * - call opcode handler
	 * - unpack
	 */

	lc_channel_unbind(chan_repl);

	//DEBUG("message says '%.*s'", (int)msg->len, (char *)msg->data);
}

void handle_err(int err)
{
	TRACE("auth.so %s()", __func__);
	DEBUG("handle_err() err=%i", err);
}
