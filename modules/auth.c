/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "auth.h"
#include "../src/log.h"
#include "../src/wire.h"
#include <assert.h>
#include <librecast.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

static void auth_op_noop(lc_message_t *msg)
{
	TRACE("auth.so %s()", __func__);
};

static void auth_op_user_add(lc_message_t *msg)
{
	TRACE("auth.so %s()", __func__);

	struct iovec data = { .iov_base = msg->data, .iov_len = msg->len };
	//struct iovec repl;
	//struct iovec user;
	//struct iovec mail;
	//struct iovec pass;
	//struct iovec serv;
	//struct iovec *iovs[] = { &repl, &user, &mail, &pass, &serv };
	struct iovec iovs[5] = {};
	const int iov_count = sizeof iovs / sizeof iovs[0];
	uint8_t op, flags;

	wire_unpack(&data, iovs, iov_count, &op, &flags);
	assert(op == AUTH_OP_USER_ADD);
	assert(flags == 7);
	assert(strncmp(iovs[0].iov_base, "aaaa", iovs[0].iov_len) == 0);
	for (int i = 0; i < iov_count; i++) {
		DEBUG("[%i] (%zu) '%.*s'", i, iovs[i].iov_len, (int)iovs[i].iov_len, iovs[i].iov_base);
	}

	/* TODO 
	 * - map fields to opcodes in auth.h
	 * - wire_unpack() here
	 * - process */
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

	DEBUG("%zu bytes received", msg->len);

	/* TODO: read opcode and pass to handler */
	uint8_t opcode = *((uint8_t *)msg->data);
	DEBUG("opcode read: %u", opcode);

	switch (opcode) {
		AUTH_OPCODES(AUTH_OPCODE_FUN)
	default:
		ERROR("Invalid auth opcode received: %u", opcode);
	}

	//lc_ctx_t *lctx = lc_ctx_new();
	//lc_ctx_t *lctx = lc_channel_ctx(msg->chan);
	//lc_socket_t *sock = lc_channel_socket(msg->chan);
	//lc_socket_t *sock = lc_socket_new(lctx);
	//lc_channel_t *chan_repl = lc_channel_new(lctx, "repl");
	//DEBUG("auth.so binding socket");
	//lc_channel_bind(sock, chan_repl);
	//lc_msg_send(chan_repl, msg);

	/* TODO:
	 * - decrypt
	 * - call opcode handler
	 * - unpack
	 */

	//lc_channel_unbind(chan_repl);

	//DEBUG("message says '%.*s'", (int)msg->len, (char *)msg->data);
}

void handle_err(int err)
{
	TRACE("auth.so %s()", __func__);
	DEBUG("handle_err() err=%i", err);
}
