/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "auth.h"
#include "../src/config.h"
#include "../src/log.h"
#include "../src/wire.h"
#include <assert.h>
#include <curl/curl.h>
#include <librecast.h>
#include <sodium.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* TODO: from config */
#define FROM "noreply@librecast.net"

static int auth_mail_token(char *subject, char *to, char *token)
{
	char filename[] = "/tmp/lsd-auth-mail-XXXXXX";
	FILE *f;
	time_t t;
	int ret = 0;
	int fd;

	if ((fd = mkstemp(filename)) == -1) {
		ERROR("error creating tempfile: %s", strerror(errno));
		return -1;
	}
	if ((f = fdopen(fd, "w")) == NULL) {
		close(fd);
		return -1;
	}

	t = time(NULL);
	char ts[40];
	char welcometext[] = "You (or someone on your behalf) has signed up to Librecast Live using this email address.  To verify your address, please click the following link\r\n";
	strftime(ts, sizeof ts, "%a, %d %b %Y %T %z", localtime(&t));
	fprintf(f, "Date: %s\r\n", ts);
	fprintf(f, "From: %s\r\n", FROM); /* TODO: from config */
	fprintf(f, "To: Librecast Live <%s>\r\n", to);
	fprintf(f, "Subject: %s\r\n", subject);
	fprintf(f, "\r\n"); /* blank line */
	fprintf(f, "%s", welcometext); /* TODO: from config */
	fprintf(f, "    https://live.librecast.net/verifyemail/%s\r\n", token);
	fprintf(f, "We look forward to you joining us soon!\r\n");
	fflush(f); rewind(f);

	/* send email */
	CURL *curl = NULL;
	CURLcode res = CURLE_OK;
	struct curl_slist *recipients = NULL;
	if (curl_global_init(CURL_GLOBAL_ALL)) {
		goto exit_err;
		ret = -1;
	}
	curl = curl_easy_init();
	if (curl) {
		curl_easy_setopt(curl, CURLOPT_URL, "smtp://smtp.gladserv.com:25"); /* FIXME config */
		curl_easy_setopt(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);
		curl_easy_setopt(curl, CURLOPT_MAIL_FROM, FROM);
		recipients = curl_slist_append(recipients, to);
		curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);
		curl_easy_setopt(curl, CURLOPT_READDATA, f);
		curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
		if (config.debug) curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
		if (curl_easy_perform(curl) != CURLE_OK) {
			ERROR("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
		}
		curl_slist_free_all(recipients);
		curl_easy_cleanup(curl);
	}
	curl_global_cleanup();
exit_err:
	fclose(f);
	close(fd);
	unlink(filename);
	return ret;
}

static void auth_op_noop(lc_message_t *msg)
{
	TRACE("auth.so %s()", __func__);
};

static void auth_op_user_add(lc_message_t *msg)
{
	TRACE("auth.so %s()", __func__);

	assert(config.handlers != NULL);

	/* TODO: move this whole mess to handle_msg() */

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
	if (sodium_init() == -1) {
		ERROR("error initalizing libsodium");
		return;
	}

	unsigned char data[pkt.iov_len - crypto_box_MACBYTES];
	unsigned char privatekey[crypto_box_SECRETKEYBYTES];
	unsigned char *senderkey = payload[0].iov_base;
	unsigned char *nonce = payload[1].iov_base;

	/* convert private key from hex 2 bin */
	sodium_hex2bin(privatekey,
			crypto_box_SECRETKEYBYTES,
			config.handlers->key_private,
			crypto_box_SECRETKEYBYTES * 2,
			NULL,
			0,
			NULL);

	if (crypto_box_open_easy(data, payload[2].iov_base, payload[2].iov_len,
				nonce, senderkey, privatekey) != 0)
	{
		ERROR("crypto_box_open_easy() failed");
		return;
	}
	DEBUG("auth module decryption successful");

	/* (1b) unpack inner data fields */
	DEBUG("auth module unpacking fields");
	const int iov_count = 5;
	struct iovec iovs[iov_count];
	struct iovec clearpkt = { .iov_base = data, .iov_len = pkt.iov_len - crypto_box_MACBYTES };
	wire_unpack(&clearpkt,
			iovs,
			iov_count,
			&op,
			&flags);
	for (int i = 1; i < iov_count; i++) {
		DEBUG("[%i] %.*s", i, (int)iovs[i].iov_len, (char *)iovs[i].iov_base);
	}

	/* TODO: validate things like email address */

	/* (2) create token */
	unsigned char token[crypto_box_PUBLICKEYBYTES];
	const size_t hexlen = crypto_box_PUBLICKEYBYTES * 2 + 1;
	char hextoken[hexlen];
	if (config.testmode) {
		unsigned char seed[randombytes_SEEDBYTES];
		memcpy(seed, senderkey, randombytes_SEEDBYTES);
		randombytes_buf_deterministic(token, sizeof token, seed);
	}
	else randombytes_buf(token, sizeof token);
	sodium_bin2hex(hextoken, hexlen, token, sizeof token);
	DEBUG("token created: %s", hextoken);

	/* TODO: (3) create user record in db */
	char pwhash[crypto_pwhash_STRBYTES];

	/* create userid */
	unsigned char userid_bytes[crypto_box_PUBLICKEYBYTES];
	char userid[hexlen];
	randombytes_buf(userid_bytes, sizeof userid_bytes);
	sodium_bin2hex(userid, hexlen, userid_bytes, sizeof userid_bytes);
	DEBUG("userid created: %s", userid);

	/* hash password */
	if (crypto_pwhash_str(pwhash, iovs[3].iov_base, iovs[3].iov_len,
			crypto_pwhash_OPSLIMIT_INTERACTIVE,
			crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0)
	{
		ERROR("crypto_pwhash() error");
	}
	/* TODO: store userid */
	/* TODO: store password */
	/* TODO: store email */
	/* TODO: store token + expiry */
	/* TODO: any indexes needed */
	/* TODO: logfile entry */
	DEBUG("user created");

	/* TODO: (4) email token */
	DEBUG("emailing token");
	char subject[] = "Librecast Live - Confirm Your Email Address";
	char *to = strndup(iovs[2].iov_base, iovs[2].iov_len);
	if (auth_mail_token(subject, to, hextoken) == -1) {
		ERROR("error in auth_mail_token()");
	}
	else {
		DEBUG("email sent");
	}
	free(to);

	/* (5) reply to reply address */
	DEBUG("response to requestor");
	lc_ctx_t *lctx;
	lc_socket_t *sock;
	lc_channel_t *chan;
	lc_message_t response;
	lctx = lc_ctx_new();
	sock = lc_socket_new(lctx);
	chan = lc_channel_nnew(lctx, senderkey, crypto_box_PUBLICKEYBYTES);
	lc_channel_bind(sock, chan);
	lc_msg_init_size(&response, 2); /* just an opcode + flag really */
	((uint8_t *)response.data)[0] = AUTH_OP_NOOP;	/* TODO: response opcode */
	((uint8_t *)response.data)[1] = 7;		/* TODO: define response codes */
	int opt = 1; /* set loopback in case we're on the same host as the sender */
	lc_socket_setopt(sock, IPV6_MULTICAST_LOOP, &opt, sizeof(opt));
	lc_msg_send(chan, &response);
	lc_ctx_free(lctx);
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
