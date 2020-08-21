/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "auth.h"
#include "../src/config.h"
#include "../src/log.h"
#include "../src/wire.h"
#include <assert.h>
#include <curl/curl.h>
#include <librecast.h>
#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* TODO: from config */
#define FROM "noreply@librecast.net"

lc_ctx_t *lctx;

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

lc_ctx_t *auth_init()
{
	lctx = lc_ctx_new();
	handler_t *h = config.handlers;
	if (h && h->dbpath) {
		if (mkdir(h->dbpath, S_IRWXU) == -1 && errno != EEXIST) {
			ERROR("can't create database path '%s': %s", h->dbpath, strerror(errno));
		}
		lc_db_open(lctx, h->dbpath);
	}
	return lctx;
}

void auth_free()
{
	lc_ctx_free(lctx);
}

int auth_field_del(char *key, size_t keylen, char *field, void *data, size_t datalen)
{
	int ret = 0;
	unsigned char hash[crypto_generichash_BYTES] = "";
	hash_field(hash, sizeof hash, key, keylen, field, strlen(field));
	if ((ret = lc_db_del(lctx, config.handlers->dbname, hash, sizeof hash, data, datalen))) {
		errno = ret;
		ret = -1;
	}
	return ret;
}

int auth_field_get(char *key, size_t keylen, char *field, void *data, size_t *datalen)
{
	int ret = 0;
	unsigned char hash[crypto_generichash_BYTES] = "";
	hash_field(hash, sizeof hash, key, keylen, field, strlen(field));
	if ((ret = lc_db_get(lctx, config.handlers->dbname, hash, sizeof hash, data, datalen))) {
		errno = ret;
		ret = -1;
	}
	return ret;
}

int auth_field_delv(char *key, size_t keylen, char *field, struct iovec *data)
{
	return auth_field_del(key, keylen, field, data->iov_base, data->iov_len);
}

int auth_field_getv(char *key, size_t keylen, char *field, struct iovec *data)
{
	return auth_field_get(key, keylen, field, &data->iov_base, &data->iov_len);
}

int auth_field_set(char *key, size_t keylen, const char *field, void *data, size_t datalen)
{
	unsigned char hash[crypto_generichash_BYTES];
	hash_field(hash, sizeof hash, key, keylen, field, strlen(field));
	return lc_db_set(lctx, config.handlers->dbname, hash, sizeof hash, data, datalen);
}

int auth_user_pass_set(char *userid, struct iovec *pass)
{
	char pwhash[crypto_pwhash_STRBYTES];
	if (crypto_pwhash_str(pwhash, pass->iov_base, pass->iov_len,
			crypto_pwhash_OPSLIMIT_INTERACTIVE,
			crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0)
	{
		ERROR("crypto_pwhash() error");
		return -1;
	}
	return auth_field_set(userid, AUTH_HEXLEN, "pass", pwhash, sizeof pwhash);
}

int auth_user_create(char *userid, struct iovec *mail, struct iovec *pass)
{
	unsigned char userid_bytes[crypto_box_PUBLICKEYBYTES];
	struct iovec nopass = {0};
	struct iovec user = {0};

	if (!auth_valid_email(mail->iov_base, mail->iov_len)) {
		errno = EINVAL;
		return -1;
	}
	if (!auth_user_bymail(mail, &user)) {
		free(user.iov_base);
		errno = EADDRINUSE;
		return -1;
	}

	/* we don't do any strength checking on passwords here
	 * save that for the UI where we can give proper feedback */
	if (pass && !pass->iov_len) return -1;
	if (!pass) pass = &nopass;

	randombytes_buf(userid_bytes, sizeof userid_bytes);
	sodium_bin2hex(userid, AUTH_HEXLEN, userid_bytes, sizeof userid_bytes);
	DEBUG("userid created: %s", userid);
	if (auth_user_pass_set(userid, pass)) {
		ERROR("failed to set password");
		return -1;
	}
	auth_field_set(userid, AUTH_HEXLEN, "mail", mail->iov_base, mail->iov_len);
	auth_field_set(mail->iov_base, mail->iov_len, "user", userid, AUTH_HEXLEN);
	return 0;
}

int auth_user_bymail(struct iovec *mail, struct iovec *userid)
{
	DEBUG("searching for mail: %.*s", (int)mail->iov_len, (char *)mail->iov_base);
	return auth_field_get(mail->iov_base, mail->iov_len, "user",
			&userid->iov_base,
			&userid->iov_len);
}

/* minimal email verification - our smtp server will do the rest */
int auth_valid_email(char *mail, size_t len)
{
	char *at, *end;
	end = mail + len;
	if (len < 3) return 0;		/* too short at least 3 chars eg. a@b */
	mail++; len--;			/* must have at least one char for local part */
	at = memchr(mail, '@', len);
	if (!at) return 0;		/* check for '@' */
	if (at + 1 >= end) return 0;	/* no domain part */
	return 1;
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
		DEBUG("to: %s", to);
		if (!recipients) {
			ERROR("unable to append recipients");
			ret = -1;
			goto cleanup;
		}
		curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);
		curl_easy_setopt(curl, CURLOPT_READDATA, f);
		curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
		if (config.debug) curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
		if (curl_easy_perform(curl) != CURLE_OK) {
			ERROR("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
			ret = -1;
		}
cleanup:
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

int auth_decode_packet(lc_message_t *msg, auth_payload_t *payload)
{
	/* unpack outer packet [opcode][flags] + [public key][nonce][payload] */
	DEBUG("auth module unpacking outer packet of %zu bytes", msg->len);
	enum { /* outer fields */
		fld_key,
		fld_nonce,
		fld_payload,
		outerfields
	};
	struct iovec pkt = { .iov_base = msg->data, .iov_len = msg->len };
	uint8_t op, flags;
	struct iovec outer[outerfields] = {0};

	if (wire_unpack(&pkt, outer, outerfields, &op, &flags) == -1) {
		errno = EBADMSG;
		return -1;
	}
	/* outer fields are all required */
	if ((outer[fld_key].iov_len != crypto_box_PUBLICKEYBYTES)
	||  (outer[fld_nonce].iov_len != crypto_box_NONCEBYTES)
	||  (outer[fld_payload].iov_len < 1)) {
		errno = EBADMSG;
		return -1;
	}
	DEBUG("auth module decrypting contents");
	if (sodium_init() == -1) {
		ERROR("error initalizing libsodium");
		return -1;
	}

	payload->data = malloc(outer[fld_payload].iov_len - crypto_box_MACBYTES);
	unsigned char privatekey[crypto_box_SECRETKEYBYTES];
	payload->senderkey = outer[fld_key];
	unsigned char *nonce = outer[fld_nonce].iov_base;
	auth_key_crypt_sk_bin(privatekey, config.handlers->key_private);
	if (crypto_box_open_easy(payload->data,
				outer[fld_payload].iov_base,
				outer[fld_payload].iov_len,
				nonce, payload->senderkey.iov_base, privatekey) != 0)
	{
		ERROR("packet decryption failed");
		return -1;
	}
	DEBUG("auth module decryption successful");

	/* unpack inner data fields */
	DEBUG("auth module unpacking fields");
	struct iovec clearpkt = {0};
	clearpkt.iov_base = payload->data;
	clearpkt.iov_len = outer[fld_payload].iov_len - crypto_box_MACBYTES;
	if (wire_unpack_pre(&clearpkt, payload->fields, payload->fieldcount, NULL, 0) == -1)
		return -1;
	DEBUG("wire_unpack() fieldcount: %i", payload->fieldcount);
	DEBUG("wire_unpack() done, dumping fields...");

	for (int i = 0; i < payload->fieldcount; i++) {
		DEBUG("[%i] %zu bytes", i, payload->fields[i].iov_len);
	}
	for (int i = 0; i < payload->fieldcount; i++) {
		DEBUG("[%i] %.*s", i, (int)payload->fields[i].iov_len, (char *)payload->fields[i].iov_base);
	}

	return 0;
}

int auth_reply(struct iovec *repl, struct iovec *key, struct iovec *data, uint8_t op, uint8_t flags)
{
	DEBUG("response to requestor");
	lc_socket_t *sock = NULL;
	lc_channel_t *chan = NULL;
	lc_message_t response = {0};
	sock = lc_socket_new(lctx);
	chan = lc_channel_nnew(lctx, key->iov_base, crypto_box_PUBLICKEYBYTES);
	lc_channel_bind(sock, chan);
	lc_msg_init_size(&response, 2); /* just an opcode + flag really */
	((uint8_t *)response.data)[0] = op;	/* TODO: response opcode */
	((uint8_t *)response.data)[1] = flags;	/* TODO: define response codes */
	int opt = 1; /* set loopback in case we're on the same host as the sender */
	lc_socket_setopt(sock, IPV6_MULTICAST_LOOP, &opt, sizeof(opt));
	lc_msg_send(chan, &response);
	lc_msg_free(&response);
	return 0;
};

int auth_user_pass_verify(struct iovec *user, struct iovec *pass)
{
	int ret = 0;
	struct iovec pwhash = {0};
	struct iovec *pw = &pwhash;
	struct iovec nopass = { .iov_base = "*", .iov_len = 1 };
	if (auth_field_getv(user->iov_base, AUTH_HEXLEN, "pass", &pwhash))
	{
		DEBUG("unable to find password for user");
		pw = &nopass; /* preserve constant time */
	}
	else if (pw->iov_len == 0) {
		DEBUG("zero length password");
		pw = &nopass; /* preserve constant time */
	}
	if (crypto_pwhash_str_verify(pw->iov_base, pass->iov_base, pass->iov_len) != 0) {
		DEBUG("password verification failed");
		errno = EACCES;
		ret = -1;
	}
	free(pwhash.iov_base);
	return ret;
}

char *auth_key_sign_pk_hex(char *combokey)
{
	return combokey + crypto_box_PUBLICKEYBYTES * 2;
}

char *auth_key_sign_sk_hex(char *combokey)
{
	return combokey + crypto_box_SECRETKEYBYTES * 2;
}

unsigned char *auth_key_crypt_pk_bin(unsigned char *binkey, char *combokey)
{
	sodium_hex2bin(binkey, crypto_box_PUBLICKEYBYTES, combokey,
		crypto_box_PUBLICKEYBYTES * 2, NULL, 0, NULL);
	return binkey;
}

unsigned char *auth_key_crypt_sk_bin(unsigned char *binkey, char *combokey)
{
	sodium_hex2bin(binkey, crypto_box_SECRETKEYBYTES, combokey,
		crypto_box_SECRETKEYBYTES * 2, NULL, 0, NULL);
	return binkey;
}

unsigned char *auth_key_sign_pk_bin(unsigned char *binkey, char *combokey)
{
	sodium_hex2bin(binkey, crypto_sign_PUBLICKEYBYTES,
		auth_key_sign_pk_hex(combokey),
		crypto_sign_PUBLICKEYBYTES * 2, NULL, 0, NULL);
	return binkey;
}

unsigned char *auth_key_sign_sk_bin(unsigned char *binkey, char *combokey)
{
	sodium_hex2bin(binkey, crypto_sign_SECRETKEYBYTES,
		auth_key_sign_sk_hex(combokey),
		crypto_sign_SECRETKEYBYTES * 2, NULL, 0, NULL);
	return binkey;
}

int auth_serv_token_new(struct iovec *tok, struct iovec *clientkey, struct iovec *serv)
{
	unsigned char sk[crypto_sign_SECRETKEYBYTES] = {0};
	unsigned long long tok_len = 0;
	unsigned char *cap_sig;
	struct iovec data;
	struct iovec *caps[] = { clientkey, serv };
	const int iov_count = sizeof caps / sizeof caps[0];
	uint64_t expires;
	struct iovec pre[1] = {0};
	const int pre_count = sizeof pre / sizeof pre[0];
	pre[0].iov_base = &expires;
	pre[0].iov_len = sizeof expires;

	/* TODO: permission bits */

	expires = htobe64(time(NULL) + config.handlers->token_duration);
	wire_pack_pre(&data, caps, iov_count, pre, pre_count);

	cap_sig = malloc(crypto_sign_BYTES + data.iov_len);
	auth_key_sign_sk_bin(sk, config.handlers->key_private);
	if (crypto_sign(cap_sig, &tok_len, data.iov_base, data.iov_len, sk)) {
		ERROR("crypto_sign() failed");
		free(cap_sig);
		errno = EIO;
		return -1;
	}
	if (tok_len > SIZE_MAX) {
		ERROR("signed token too long");
		free(cap_sig);
		errno = EFBIG;
		return -1;
	}
	tok->iov_base = cap_sig;
	tok->iov_len = (size_t)tok_len;
	free(data.iov_base);
	return 0;
}

int auth_serv_token_get(struct iovec *tok, struct iovec *user, struct iovec *pass, struct iovec *serv)
{
	/* TODO: create token with:
	 * - senderkey
	 * - resource / service
	 * - flags (read / write etc)
	 * - signed
	 */

	return 0;
}

int auth_user_token_new(auth_user_token_t *token, auth_payload_t *payload)
{
	if (config.testmode) {
		DEBUG("auth_user_token_new(): test mode enabled");
		unsigned char seed[randombytes_SEEDBYTES];
		memcpy(seed, payload->senderkey.iov_base, randombytes_SEEDBYTES);
		randombytes_buf_deterministic(token->token, sizeof token->token, seed);
	}
	else randombytes_buf(token->token, sizeof token->token);
	sodium_bin2hex(token->hextoken, AUTH_HEXLEN, token->token, sizeof token->token);
	token->expires = htobe64((uint64_t)time(NULL) + 60 * 15); /* expires in 15 minutes */
	DEBUG("token created: %s", token->hextoken);
	return 0;
}

int auth_user_token_set(char *userid, auth_user_token_t *token)
{
	if (auth_field_set(token->hextoken, AUTH_HEXLEN - 1, "user", userid, AUTH_HEXLEN)) {
		DEBUG ("error setting user token");
		return -1;
	}
	if (auth_field_set(token->hextoken, AUTH_HEXLEN - 1, "expires",
			&token->expires, sizeof token->expires))
	{
		DEBUG ("error setting user token expiry");
		return -1;
	}
	return 0;
}

int auth_user_token_use(struct iovec *token, struct iovec *pass)
{
	int ret = 0;
	struct iovec user = {0};
	struct iovec expires = {0};
	char *userid;
	auth_user_token_t tok = {0};
	DEBUG("search for token '%.*s'", AUTH_HEXLEN - 1, (char *)token->iov_base);
	if (auth_field_getv(token->iov_base, token->iov_len, "user", &user)) {
		DEBUG("user token not found");
		return -1;
	}
	if (auth_field_getv(token->iov_base, token->iov_len, "expires", &expires)) {
		DEBUG("user token expiry not found");
		return -1;
	}
	tok.expires = *((uint64_t *)expires.iov_base);
	free(expires.iov_base);
	if (!auth_user_token_valid(&tok)) {
		DEBUG("invalid token");
		ret = -1;
		goto delete_token;
	}
	DEBUG("valid user token");
	userid = strndup(user.iov_base, user.iov_len);
	if (auth_user_pass_set(userid, pass))
		ret = -1;
	DEBUG("password set for user %s", userid);
	free(userid);
delete_token:
	free(user.iov_base);
	/* tokens are single-user - delete */
	if (auth_field_delv(token->iov_base, token->iov_len, "user", &user)) {
		ERROR("user token not deleted");
		return -1;
	}
	DEBUG("user token deleted");

	return ret;
}

int auth_user_token_valid(auth_user_token_t *token)
{
	return (be64toh(token->expires) >= time(NULL));
}

static void auth_op_noop(lc_message_t *msg)
{
	TRACE("auth.so %s()", __func__);
};

static void auth_op_user_add(lc_message_t *msg)
{
	TRACE("auth.so %s()", __func__);
	enum {
		repl,
		user,
		mail,
		pass,
		serv,
		fieldcount
	};
	struct iovec fields[fieldcount] = {0};
	auth_payload_t p = { .fields = fields, .fieldcount = fieldcount };

	if (auth_decode_packet(msg, &p) == -1) {
		perror("auth_decode_packet()");
		return;
	}
	if (!auth_valid_email(fields[mail].iov_base, fields[mail].iov_len)) {
		ERROR("invalid email address");
		return;
	}

	char userid[AUTH_HEXLEN];
	auth_user_create(userid, &fields[mail], &fields[pass]);
	auth_user_token_t token;
	auth_user_token_new(&token, &p);
	auth_user_token_set(userid, &token);
	DEBUG("user created");

	/* TODO: logfile entry */


	DEBUG("emailing token");
	if (!config.testmode) {
		char *to = strndup(fields[mail].iov_base, fields[mail].iov_len);
		char subject[] = "Librecast Live - Confirm Your Email Address";
		if (auth_mail_token(subject, to, token.hextoken) == -1) {
			ERROR("error in auth_mail_token()");
		}
		else {
			DEBUG("email sent");
		}
		free(to);
	}
	struct iovec data = {0};
	auth_reply(&fields[repl], &p.senderkey, &data, AUTH_OP_NOOP, 0x7);
	free(p.data);
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
	enum {
		tok,
		pass,
		fieldcount
	};
	struct iovec data = {0};
	struct iovec fields[fieldcount] = {0};
	auth_payload_t p = { .fields = fields, .fieldcount = fieldcount };
	if (auth_decode_packet(msg, &p) == -1) {
		perror("auth_decode_packet()");
		return;
	}
	auth_user_token_use(&fields[tok], &fields[pass]);
	auth_reply(&p.senderkey, &p.senderkey, &data, AUTH_OP_NOOP, 0x7);
	free(p.data);
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
	enum {
		repl,
		user,
		mail,
		pass,
		serv,
		fieldcount
	};
	struct iovec fields[fieldcount] = {0};
	struct iovec userid = {0};
	struct iovec cap = {0};
	lc_socket_t *sock = NULL;
	lc_channel_t *chan = NULL;
	lc_message_t response = {0};
	auth_payload_t p = {0};
	p.fields = fields;
	p.fieldcount = fieldcount;

	if (auth_decode_packet(msg, &p) == -1) {
		perror("auth_decode_packet()");
		return;
	}
	if (fields[user].iov_len > 0)
		userid = fields[user];
	else {
		/* user not supplied, look up from mail address */
		if (auth_user_bymail(&fields[mail], &userid)) {
			ERROR("no user found for '%.*s'", (int)fields[mail].iov_len,
					(char *)fields[mail].iov_base);
			return;
		}
	}
	if (auth_user_pass_verify(&userid, &fields[pass])) {
		ERROR("failed login for user %.*s", (int)userid.iov_len, (char *)userid.iov_base);
		return;
	}
	if (auth_serv_token_new(&cap, p.senderkey.iov_base, &fields[serv])) {
		perror("auth_serv_token_new()");
		return;
	}

	/* TODO: logfile entry */

	DEBUG("response to requestor");
	sock = lc_socket_new(lctx);
	chan = lc_channel_nnew(lctx, p.senderkey.iov_base, crypto_box_PUBLICKEYBYTES);
	lc_channel_bind(sock, chan);
	lc_msg_init_size(&response, 2); /* just an opcode + flag really */
	((uint8_t *)response.data)[0] = AUTH_OP_NOOP;	/* TODO: response opcode */
	((uint8_t *)response.data)[1] = 7;		/* TODO: define response codes */
	int opt = 1; /* set loopback in case we're on the same host as the sender */
	lc_socket_setopt(sock, IPV6_MULTICAST_LOOP, &opt, sizeof(opt));
	lc_msg_send(chan, &response);
	lc_msg_free(&response);
	free(p.data);
};

void init(config_t *c)
{
	TRACE("auth.so %s()", __func__);
	if (c) config = *c;
	DEBUG("I am the very model of a modern auth module");
	auth_init();
}

void finit(void)
{
	TRACE("auth.so %s()", __func__);
	auth_free();
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
