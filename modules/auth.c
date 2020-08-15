/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "auth.h"
#include "../src/config.h"
#include "../src/log.h"
#include "../src/wire.h"
#include <assert.h>
#include <curl/curl.h>
#include <librecast.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* TODO: from config */
#define FROM "noreply@librecast.net"

void hash_field(unsigned char *hash, size_t hashlen,
		const char *key, size_t keylen,
		const char *fld, size_t fldlen)
{
	crypto_generichash_state state;
	crypto_generichash_init(&state, NULL, 0, hashlen);
	crypto_generichash_update(&state, (unsigned char *)key, keylen);
	crypto_generichash_update(&state, (unsigned char *)fld, fldlen);
	crypto_generichash_final(&state, hash, hashlen);
}

void auth_field_set(lc_ctx_t *lctx, char *key, size_t keylen,
		const char *field, void *data, size_t datalen)
{
	unsigned char hash[crypto_generichash_BYTES];
	hash_field(hash, sizeof hash, key, keylen, field, strlen(field));
	lc_db_set(lctx, config.handlers->dbname, hash, sizeof hash, data, datalen);
}

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

static int auth_decode_packet(lc_message_t *msg, auth_payload_t *payload)
{
	/* unpack outer packet */
	DEBUG("auth module unpacking outer packet");
	struct iovec pkt = { .iov_base = msg->data, .iov_len = msg->len };
	uint8_t op, flags;
	struct iovec outer[3] = {};
	if (wire_unpack(&pkt, outer, 3, &op, &flags) == -1) {
		errno = EBADMSG;
		return -1;
	}

	/* decrypt payload */
	DEBUG("auth module decrypting contents");
	if (sodium_init() == -1) {
		ERROR("error initalizing libsodium");
		return -1;
	}

	unsigned char data[pkt.iov_len - crypto_box_MACBYTES];
	unsigned char privatekey[crypto_box_SECRETKEYBYTES];
	payload->senderkey = outer[0].iov_base;
	unsigned char *nonce = outer[1].iov_base;

	/* convert private key from hex 2 bin */
	sodium_hex2bin(privatekey,
			crypto_box_SECRETKEYBYTES,
			config.handlers->key_private,
			crypto_box_SECRETKEYBYTES * 2,
			NULL,
			0,
			NULL);

	if (crypto_box_open_easy(data, outer[2].iov_base, outer[2].iov_len,
				nonce, payload->senderkey, privatekey) != 0)
	{
		ERROR("packet decryption failed");
		return -1;
	}
	DEBUG("auth module decryption successful");

	/* unpack inner data fields */
	DEBUG("auth module unpacking fields");
	//const int iov_count = 5;
	//struct iovec iovs[iov_count];
	struct iovec clearpkt = { .iov_base = data, .iov_len = pkt.iov_len - crypto_box_MACBYTES };
	wire_unpack(&clearpkt,
			payload->fields,
			payload->fieldcount,
			&payload->opcode,
			&payload->flags);
	for (int i = 1; i < payload->fieldcount; i++) {
		DEBUG("[%i] %.*s", i, (int)payload->fields[i].iov_len, (char *)payload->fields[i].iov_base);
	}
	return 0;
}

int auth_create_user_token(auth_user_token_t *token, auth_payload_t *payload)
{
	if (config.testmode) {
		unsigned char seed[randombytes_SEEDBYTES];
		memcpy(seed, payload->senderkey, randombytes_SEEDBYTES);
		randombytes_buf_deterministic(token, sizeof token, seed);
	}
	else randombytes_buf(token->token, sizeof token->token);
	sodium_bin2hex(token->hextoken, AUTH_HEXLEN, token->token, sizeof token);
	token->expires = htobe64((uint64_t)time(NULL) + 60 * 15); /* expires in 15 minutes */
	DEBUG("token created: %s", token->hextoken);
	return 0;
}

static void auth_op_noop(lc_message_t *msg)
{
	TRACE("auth.so %s()", __func__);
};

static void auth_op_user_add(lc_message_t *msg)
{
	TRACE("auth.so %s()", __func__);

	lc_ctx_t *lctx;
	lc_socket_t *sock;
	lc_channel_t *chan;
	lc_message_t response;
	handler_t *h = config.handlers;
	assert(h != NULL);

	auth_payload_t p;
	const int iov_count = 5;
	struct iovec fields[iov_count];
	p.fields = fields;
	if (auth_decode_packet(msg, &p) == -1) {
		goto auth_op_user_add_exit;
	}

	/* TODO: validate things like email address */

	auth_user_token_t token;
	auth_create_user_token(&token, &p);

	/* (3) create user record in db */
	char pwhash[crypto_pwhash_STRBYTES];
	unsigned char userid_bytes[crypto_box_PUBLICKEYBYTES];
	char userid[AUTH_HEXLEN];
	randombytes_buf(userid_bytes, sizeof userid_bytes);
	sodium_bin2hex(userid, AUTH_HEXLEN, userid_bytes, sizeof userid_bytes);
	DEBUG("userid created: %s", userid);
	if (crypto_pwhash_str(pwhash, fields[3].iov_base, fields[3].iov_len,
			crypto_pwhash_OPSLIMIT_INTERACTIVE,
			crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0)
	{
		ERROR("crypto_pwhash() error");
	}

	lctx = lc_ctx_new();
	if (mkdir(h->dbpath, S_IRWXU) == -1 && errno != EEXIST) {
		ERROR("can't create database path '%s': %s", h->dbpath, strerror(errno));
	}
	lc_db_open(lctx, h->dbpath);
	auth_field_set(lctx, userid, AUTH_HEXLEN, "pkey", fields[0].iov_base, fields[0].iov_len);
	auth_field_set(lctx, userid, AUTH_HEXLEN, "mail", fields[2].iov_base, fields[2].iov_len);
	auth_field_set(lctx, fields[2].iov_base, fields[2].iov_len, "user", userid, AUTH_HEXLEN);
	auth_field_set(lctx, userid, AUTH_HEXLEN, "pass", fields[3].iov_base, fields[3].iov_len);
	auth_field_set(lctx, userid, AUTH_HEXLEN, "serv", fields[4].iov_base, fields[4].iov_len);
	auth_field_set(lctx, userid, AUTH_HEXLEN, "token", token.hextoken, AUTH_HEXLEN);
	auth_field_set(lctx, token.hextoken, AUTH_HEXLEN, "user", userid, AUTH_HEXLEN);
	auth_field_set(lctx, token.hextoken, AUTH_HEXLEN, "expires", &token.expires, sizeof token.expires);

	/* TODO: logfile entry */
	DEBUG("user created");

	/* (4) email token */
	DEBUG("emailing token");
#if 0
	char subject[] = "Librecast Live - Confirm Your Email Address";
	char *to = strndup(fields[2].iov_base, fields[2].iov_len);
	if (auth_mail_token(subject, to, token.hextoken) == -1) {
		ERROR("error in auth_mail_token()");
	}
	else {
		DEBUG("email sent");
	}
	free(to);
#endif

	/* (5) reply to reply address */
	DEBUG("response to requestor");
	sock = lc_socket_new(lctx);
	chan = lc_channel_nnew(lctx, p.senderkey, crypto_box_PUBLICKEYBYTES);
	lc_channel_bind(sock, chan);
	lc_msg_init_size(&response, 2); /* just an opcode + flag really */
	((uint8_t *)response.data)[0] = AUTH_OP_NOOP;	/* TODO: response opcode */
	((uint8_t *)response.data)[1] = 7;		/* TODO: define response codes */
	int opt = 1; /* set loopback in case we're on the same host as the sender */
	lc_socket_setopt(sock, IPV6_MULTICAST_LOOP, &opt, sizeof(opt));
	lc_msg_send(chan, &response);
auth_op_user_add_exit:
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

	DEBUG("handle_msg() - after the handler");

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
