/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "auth.h"
#include "../src/config.h"
#include "../src/log.h"
#include "../src/wire.h"
#include <assert.h>
#include <librecast.h>
#include <sodium.h>
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

	assert(config.handlers != NULL);

	//const int iov_count = 5;
	//struct iovec iovs[iov_count];

	/* (0) unpack outer packet */
	DEBUG("auth module unpacking outer packet");
	struct iovec pkt = { .iov_base = msg->data, .iov_len = msg->len };
	uint8_t op, flags;
	struct iovec payload[3] = {};
	if (wire_unpack(&pkt, payload, 3, &op, &flags) == -1) {
		errno = EBADMSG;
		return;
	}

	/* (1) decrypt packet */
	DEBUG("auth module decrypting contents");
	unsigned char data[pkt.iov_len - crypto_box_MACBYTES];
	//struct iovec iovc[5] = {};
	unsigned char privatekey[crypto_box_SECRETKEYBYTES];

	/* convert private key from hex 2 bin */
	sodium_hex2bin(&privatekey,
			crypto_box_SECRETKEYBYTES,
			config.handlers->key_private,
			crypto_box_SECRETKEYBYTES * 2,
			NULL,
			0,
			NULL);

	unsigned char *senderkey = payload[0].iov_base;
	unsigned char *nonce;
	nonce = payload[1].iov_base;

	const size_t hexlen = crypto_box_PUBLICKEYBYTES * 2 + 1;
	char hex[hexlen];
	sodium_bin2hex(hex, hexlen, privatekey, crypto_box_SECRETKEYBYTES);
	DEBUG("privatekey: %s", hex);
	sodium_bin2hex(hex, hexlen, senderkey, crypto_box_PUBLICKEYBYTES);
	DEBUG("senderkey: %s", hex);

	if (crypto_box_open_easy(data, payload[2].iov_base, payload[2].iov_len,
				nonce, senderkey, privatekey) != 0)
	{
		ERROR("crypto_box_open_easy() failed");
		return;
	}
	DEBUG("auth module decryption successful");

	/* TODO (1b) unpack inner data fields */
	DEBUG("auth module unpacking fields");
	//wire_unpack(&payload, iovs, iov_count, &op, &flags);


	/* TODO: (2) create token */
	/* TODO: (3) create user record in db */
	/* TODO: (4) email token */
	/* TODO: (5) reply to reply address */

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
	/* TODO: ensure config read */
	config_include("./0000-0009.conf"); /* FIXME */
	DEBUG("I am the very model of a modern auth module");
}

void finit(void)
{
	TRACE("auth.so %s()", __func__);
	config_free();
}

void handle_msg(lc_message_t *msg)
{
	TRACE("auth.so %s()", __func__);

	DEBUG("%zu bytes received", msg->len);

	/* TODO: read opcode and pass to handler */
	uint8_t opcode = ((uint8_t *)msg->data)[0];
	uint8_t flags = ((uint8_t *)msg->data)[1];
	DEBUG("opcode read: %u", opcode);
	DEBUG("flags read: %u", flags);

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
