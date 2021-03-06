/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only */
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
lc_db_t *lcdb;

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
		lcdb = lc_db_open(lctx, h->dbpath);
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
	if ((ret = lc_db_del(lcdb, config.handlers->dbname, hash, sizeof hash, data, datalen))) {
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
	assert(lcdb);
	if ((ret = lc_db_get(lcdb, config.handlers->dbname, hash, sizeof hash, data, datalen))) {
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
	return lc_db_set(lcdb, config.handlers->dbname, hash, sizeof hash, data, datalen);
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
	if (!pass) pass = &nopass;
#ifdef AUTH_TESTMODE
	if (config.testmode) {
		DEBUG("%s(): test mode enabled", __func__);
		unsigned char seed[randombytes_SEEDBYTES];
		memcpy(seed, mail->iov_base, randombytes_SEEDBYTES);
		randombytes_buf_deterministic(userid_bytes, sizeof userid_bytes, seed);
	}
	else
#endif
		randombytes_buf(userid_bytes, sizeof userid_bytes);
	sodium_bin2hex(userid, AUTH_HEXLEN, userid_bytes, sizeof userid_bytes);
	DEBUG("userid created: %s", userid);
	if (auth_user_pass_set(userid, pass)) {
		ERROR("failed to set password");
		free(user.iov_base);
		errno = EIO;
		return -1;
	}
	auth_field_set(userid, AUTH_HEXLEN, "mail", mail->iov_base, mail->iov_len);
	auth_field_set(mail->iov_base, mail->iov_len, "user", userid, AUTH_HEXLEN);
	free(user.iov_base);
	return 0;
}

int auth_user_bymail(struct iovec *mail, struct iovec *userid)
{
	DEBUG("searching for mail: %.*s", FMTP(mail));
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

int auth_decode_packet_key(lc_message_t *msg, auth_payload_t *payload, unsigned char *sk)
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
		perror("wire_unpack()");
		errno = EBADMSG;
		return -1;
	}
	/* outer fields are all required */
	if ((outer[fld_key].iov_len != crypto_box_PUBLICKEYBYTES)
	||  (outer[fld_nonce].iov_len != crypto_box_NONCEBYTES)
	||  (outer[fld_payload].iov_len < 1)) {
		ERROR("no payload");
		errno = EBADMSG;
		return -1;
	}
	DEBUG("auth module decrypting contents");
	if (sodium_init() == -1) {
		ERROR("error initalizing libsodium");
		return -1;
	}

	payload->data = malloc(outer[fld_payload].iov_len - crypto_box_MACBYTES);
	payload->senderkey = outer[fld_key];
	unsigned char *nonce = outer[fld_nonce].iov_base;
	if (crypto_box_open_easy(payload->data,
				outer[fld_payload].iov_base,
				outer[fld_payload].iov_len,
				nonce, payload->senderkey.iov_base, sk) != 0)
	{
		ERROR("packet decryption failed");
		errno = EBADMSG;
		return -1;
	}
	DEBUG("auth module decryption successful");

	/* unpack inner data fields */
	DEBUG("auth module unpacking fields");
	struct iovec clearpkt = {0};
	clearpkt.iov_base = payload->data;
	clearpkt.iov_len = outer[fld_payload].iov_len - crypto_box_MACBYTES;
	if (payload->fieldcount && wire_unpack_pre(&clearpkt, payload->fields, payload->fieldcount, NULL, 0) == -1)
		return -1;
	DEBUG("wire_unpack() fieldcount: %i", payload->fieldcount);
#if 0
	DEBUG("wire_unpack() done, dumping fields...");

	for (int i = 0; i < payload->fieldcount; i++) {
		DEBUG("[%i] %zu bytes", i, payload->fields[i].iov_len);
	}
	for (int i = 0; i < payload->fieldcount; i++) {
		DEBUG("[%i] %.*s", i, (int)payload->fields[i].iov_len, (char *)payload->fields[i].iov_base);
	}
#endif
	return 0;
}

int auth_decode_packet(lc_message_t *msg, auth_payload_t *payload)
{
	unsigned char sk[crypto_box_SECRETKEYBYTES];
	auth_key_crypt_sk_bin(sk, config.handlers->key_private);
	return auth_decode_packet_key(msg, payload, sk);
}

int auth_reply(struct iovec *repl, struct iovec *clientkey, struct iovec *data,
		uint8_t op, uint8_t flags)
{
	TRACE("%s(): %i", __func__, flags);
	/* encrypt payload */
	const size_t cipherlen = crypto_box_MACBYTES + data->iov_len;
	unsigned char authpubkey[crypto_box_PUBLICKEYBYTES];
	unsigned char authseckey[crypto_box_SECRETKEYBYTES];
	unsigned char nonce[crypto_box_NONCEBYTES];
	unsigned char ciphertext[cipherlen];
	struct iovec iovkey = { .iov_base = authpubkey, .iov_len = crypto_box_PUBLICKEYBYTES };
	struct iovec iovnon = { .iov_base = nonce, .iov_len = crypto_box_NONCEBYTES };
	struct iovec crypted = { .iov_base = ciphertext, .iov_len = cipherlen };
	struct iovec payload[] = { iovkey, iovnon, crypted };
	const size_t paylen = sizeof payload / sizeof payload[0];
	struct iovec pkt = {0};
	auth_key_crypt_pk_bin(authpubkey, config.handlers->key_public);
	auth_key_crypt_sk_bin(authseckey, config.handlers->key_private);
	randombytes_buf(nonce, sizeof nonce);
	if (crypto_box_easy(ciphertext, (unsigned char *)data->iov_base, data->iov_len,
				nonce, clientkey->iov_base, authseckey) == -1)
	{
		return -1;
	}

	/* pack outer */
	wire_pack(&pkt, payload, paylen, op, flags);

	/* send message */
	lc_socket_t *sock = NULL;
	lc_channel_t *chan = NULL;
	lc_message_t response = {0};
	DEBUG("response to requestor");
	sock = lc_socket_new(lctx);
	chan = lc_channel_nnew(lctx, repl->iov_base, repl->iov_len);
	lc_channel_bind(sock, chan);
	lc_msg_init_data(&response, pkt.iov_base, pkt.iov_len, NULL, NULL);
	int opt = 1; /* set loopback in case we're on the same host as the sender */
	lc_socket_setopt(sock, IPV6_MULTICAST_LOOP, &opt, sizeof(opt));
	lc_msg_send(chan, &response);
	free(pkt.iov_base);
	lc_channel_free(chan);
	lc_socket_close(sock);
	return 0;
}

static void auth_reply_code(struct iovec *repl, struct iovec *clientkey, uint8_t op, uint8_t code)
{
	TRACE("%s(): %i", __func__, code);
	struct iovec data = { .iov_base = &code, .iov_len = 1 };
	struct iovec packed = {0};
	if (wire_pack_pre(&packed, NULL, 0, &data, 1) == -1) {
		return;
	}
	auth_reply(repl, clientkey, &packed, op, code);
	free(packed.iov_base);
}

int auth_user_pass_verify(struct iovec *user, struct iovec *pass)
{
	int ret = 0;
	struct iovec pwhash = {0};
	struct iovec *pw = &pwhash;
	struct iovec nopass = { .iov_base = "*", .iov_len = 1 };
	if (auth_field_getv(user->iov_base, AUTH_HEXLEN, "pass", &pwhash))
	{
		DEBUG("unable to find password for user '%.*s", FMTP(user));
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

char *auth_key_sign_sk_hex(char *combokey){
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

int auth_serv_token_new(struct iovec *tok, struct iovec *iov, size_t iovlen)
{
	unsigned char sk[crypto_sign_SECRETKEYBYTES] = {0};
	unsigned long long tok_len = 0;
	unsigned char *cap_sig;
	struct iovec data;
	uint64_t expires;
	const int pre_count = 1;
	struct iovec pre[pre_count];
	pre[0].iov_base = &expires;
	pre[0].iov_len = sizeof expires;
	expires = htobe64(time(NULL) + config.handlers->token_duration);
	if (wire_pack_pre(&data, iov, iovlen, pre, pre_count) == -1) {
		perror("wire_pack_pre()");
		return -1;
	}
	cap_sig = malloc(crypto_sign_BYTES + data.iov_len);
	if (cap_sig == NULL) {
		free(data.iov_base);
		errno = ENOMEM;
		return -1;
	}
	DEBUG("unsigned token is %zu bytes", data.iov_len);
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

int auth_user_token_new(auth_user_token_t *token, auth_payload_t *payload)
{
#ifdef AUTH_TESTMODE
	if (config.testmode) {
		DEBUG("%s(): test mode enabled", __func__);
		unsigned char seed[randombytes_SEEDBYTES];
		memcpy(seed, payload->senderkey.iov_base, randombytes_SEEDBYTES);
		randombytes_buf_deterministic(token->token, sizeof token->token, seed);
	}
	else
#endif
		randombytes_buf(token->token, sizeof token->token);
	sodium_bin2hex(token->hextoken, AUTH_HEXLEN, token->token, sizeof token->token);
	token->expires = htobe64((uint64_t)time(NULL) + config.handlers->usertoken_expires);
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

uint8_t auth_user_token_use(struct iovec *token, struct iovec *pass)
{
	uint8_t code = 0;
	struct iovec user = {0};
	struct iovec expires = {0};
	char *userid;
	auth_user_token_t tok = {0};
	DEBUG("search for token '%.*s'", FMTP(token));
	if (auth_field_getv(token->iov_base, token->iov_len, "user", &user)) {
		DEBUG("user token not found");
		return 1;
	}
	assert(user.iov_len > 0);
	DEBUG("token matches user '%.*s'", FMTV(user));
	if (auth_field_getv(token->iov_base, token->iov_len, "expires", &expires)) {
		DEBUG("user token expiry not found");
		return 1;
	}
	tok.expires = *((uint64_t *)expires.iov_base);
	free(expires.iov_base);
	if (!auth_user_token_valid(&tok)) {
		DEBUG("invalid token");
		code = 1;
		goto delete_token;
	}
	DEBUG("valid user token");
	userid = strndup(user.iov_base, user.iov_len);
	if (auth_user_pass_set(userid, pass)) {
		code = 1;
	}
	DEBUG("password set for user %s", userid);
	free(userid);
delete_token:
	free(user.iov_base);
	/* tokens are single-use - delete */
	if (auth_field_delv(token->iov_base, token->iov_len, "user", &user)) {
		ERROR("user token not deleted");
	}
	else {
		DEBUG("user token deleted");
	}
	return code;
}

int auth_user_token_valid(auth_user_token_t *token)
{
	return (be64toh(token->expires) >= (uint64_t)time(NULL));
}

static void auth_op_noop(lc_message_t *msg)
{
	(void)msg;
	TRACE("auth.so %s()", __func__);
}

static void auth_op_user_add(lc_message_t *msg)
{
	TRACE("auth.so %s()", __func__);
	uint8_t code = 0;
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
		ERROR("invalid email address: '%.*s'", FMTV(fields[mail]));
		code = 1;
		goto reply_to_sender;
	}

	char userid[AUTH_HEXLEN] = "";
	if (auth_user_create(userid, &fields[mail], &fields[pass])) {
		perror("auth_user_create");
		code = 1;
		goto reply_to_sender;
	}
	auth_user_token_t token = {0};
	auth_user_token_new(&token, &p);
	auth_user_token_set(userid, &token);
	DEBUG("user created '%s'", userid);

	/* TODO: logfile entry */


	DEBUG("emailing token");
	if (!config.testmode) {
		char *to = strndup(fields[mail].iov_base, fields[mail].iov_len);
		char subject[] = "Librecast Live - Confirm Your Email Address";
		if (auth_mail_token(subject, to, token.hextoken) == -1) {
			perror("auth_mail_token()");
			code = 1;
		}
		else {
			DEBUG("email sent");
		}
		free(to);
	}
reply_to_sender:
	auth_reply_code(&fields[repl], &p.senderkey, AUTH_OP_USER_ADD, code);
	free(p.data);
}

static void auth_op_user_unlock(lc_message_t *msg)
{
	TRACE("auth.so %s()", __func__);
	uint8_t code;
	enum {
		repl,
		tok,
		pass,
		fieldcount
	};
	struct iovec fields[fieldcount] = {0};
	struct iovec data = {0};
	struct iovec iov = { .iov_base = "hi", .iov_len = 2 };
	auth_payload_t p = { .fields = fields, .fieldcount = fieldcount };
	if (auth_decode_packet(msg, &p) == -1) {
		perror("auth_decode_packet()");
		return;
	}
	code = auth_user_token_use(&fields[tok], &fields[pass]);
	if (wire_pack_pre(&data, &iov, 1, NULL, 0) == -1)
		perror("wire_pack_pre()");
	else
		auth_reply_code(&fields[repl], &p.senderkey, AUTH_OP_USER_UNLOCK, code);
	free(p.data);
	free(data.iov_base);
}

static void auth_op_auth_service(lc_message_t *msg)
{
	TRACE("auth.so %s()", __func__);
	uint8_t code = 0;
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
	struct iovec data = {0};
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
			ERROR("no user found for '%.*s'", FMTV(fields[mail]));
			code = 1;
			goto reply_to_sender;
		}
	}
	if (auth_user_pass_verify(&userid, &fields[pass])) {
		ERROR("failed login for user %.*s", FMTV(userid));
		code = 1;
		goto reply_to_sender;
	}
	DEBUG("successful login for user %.*s", FMTV(userid));
	struct iovec iov[] = { p.senderkey, fields[serv], userid };
	const int iovlen = sizeof iov / sizeof iov[0];
	if (auth_serv_token_new(&cap, iov, iovlen)) {
		perror("auth_serv_token_new()");
		code = 2; /* internal server error */
		goto reply_to_sender;
	}

	/* TODO: logfile entry */

	DEBUG("cap token length is %zu", cap.iov_len);
	struct iovec iovcode = { .iov_base = &code, .iov_len = 1 };
	if (wire_pack_pre(&data, &cap, 1, &iovcode, 1) == -1) {
		perror("wire_pack_pre()");
		code = 2; /* internal server error */
	}
	else
		auth_reply(&fields[repl], &p.senderkey, &data, AUTH_OP_AUTH_SERV, code);
reply_to_sender:
	if (code)
		auth_reply_code(&fields[repl], &p.senderkey, AUTH_OP_AUTH_SERV, code);
	free(p.data);
	free(data.iov_base);
	free(cap.iov_base);
	if (!fields[user].iov_len) free(userid.iov_base);
}

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
	uint8_t opcode = ((uint8_t *)msg->data)[0];
	uint8_t flags = ((uint8_t *)msg->data)[1];
	DEBUG("opcode read: %u", opcode);
	DEBUG("flags read: %u", flags);
	switch (opcode) {
		AUTH_OPCODES(AUTH_OPCODE_FUN)
	default:
		ERROR("Invalid auth opcode received: %u", opcode);
	}
	DEBUG("handle_msg() - handler exiting");
}

void handle_err(int err)
{
	TRACE("auth.so %s()", __func__);
	DEBUG("handle_err() err=%i", err);
}
