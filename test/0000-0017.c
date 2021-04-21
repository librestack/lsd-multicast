/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../modules/auth.h"
#include "../src/config.h"
#include "../src/server.h"
#include "../src/wire.h"
#include <assert.h>
#include <librecast.h>
#include <pthread.h>
#include <signal.h>
#include <sodium.h>
#include <unistd.h>

lc_ctx_t *lctx = NULL;

void *testthread(void *arg)
{
	test_log("test thread starting");
	lc_socket_t *sock, *sock_repl;
	lc_channel_t *chan, *chan_repl;
	lc_message_t msg, msg_repl;
	int opt = 1;
	struct iovec data;
	handler_t *h = config.handlers;
	test_assert(h != NULL, "handlers");

	/* generate keypair & use as reply address */
	unsigned char pk[crypto_box_PUBLICKEYBYTES];
	unsigned char sk[crypto_box_SECRETKEYBYTES];
	test_assert(sodium_init() != -1, "sodium_init()");
	test_assert(crypto_box_keypair(pk, sk) != -1, "crypto_box_keypair()");

	/* create user + token to validate */
	auth_init();
	auth_user_token_t token = {0};
	auth_payload_t p = {0};
	p.senderkey.iov_base = config.handlers->key_public;
	p.senderkey.iov_len = strlen(config.handlers->key_public);
	char userid[AUTH_HEXLEN];
	struct iovec mail = { .iov_base = "posty@example.com" };
	mail.iov_len = strlen(mail.iov_base);
	auth_user_create(userid, &mail, NULL);
	test_assert(auth_user_token_new(&token, &p) == 0, "auth_user_token_new()");
	test_assert(auth_user_token_set("fred", &token) == 0, "auth_user_token_set()");
	auth_free();

	/* (1) build packet */
	struct iovec iovs[] = {
		{ .iov_base = pk, .iov_len = crypto_box_PUBLICKEYBYTES },
		{ .iov_base = token.hextoken },
		{ .iov_base = "password" }
	};
	const int iov_count = sizeof iovs / sizeof iovs[0];
	uint8_t op = AUTH_OP_USER_UNLOCK;
	uint8_t flags = 0;
	ssize_t len;
	for (int i = 1; i < iov_count; i++) {
		iovs[i].iov_len = strlen(iovs[i].iov_base);
	}
	len = wire_pack_pre(&data, iovs, iov_count, NULL, 0);
	test_assert(len > 0, "wire_pack() returned %i", len);

	/* (2) encrypt packet */
	char *authpubhex = h->key_public;
	unsigned char authpubkey[crypto_box_PUBLICKEYBYTES];
	unsigned char nonce[crypto_box_NONCEBYTES];
	const size_t cipherlen = crypto_box_MACBYTES + data.iov_len;
	unsigned char ciphertext[cipherlen];

	auth_key_crypt_pk_bin(authpubkey, authpubhex);
	randombytes_buf(nonce, sizeof nonce);
	test_assert(!crypto_box_easy(ciphertext, (unsigned char *)data.iov_base, data.iov_len, nonce, authpubkey, sk), "crypto_box_easy()");

	/* (2b) now pack encrypted payload with public key and nonce prepended */
	struct iovec payload[] = {
		{ .iov_base = pk, .iov_len = crypto_box_PUBLICKEYBYTES },
		{ .iov_base = nonce, .iov_len = crypto_box_NONCEBYTES },
		{ .iov_base = ciphertext, .iov_len = cipherlen }
	};
	struct iovec pkt;
	len = wire_pack(&pkt, payload, 3, op, flags);

	/* (3) bind to send/receive channels, join recv channel */
	lctx = lc_ctx_new();
	sock = lc_socket_new(lctx);
	sock_repl = lc_socket_new(lctx);
	lc_socket_setopt(sock, IPV6_MULTICAST_LOOP, &opt, sizeof(opt));
	chan = lc_channel_new(lctx, authpubhex);
	chan_repl = lc_channel_nnew(lctx, pk, crypto_box_PUBLICKEYBYTES);
	lc_channel_bind(sock, chan);
	lc_channel_bind(sock_repl, chan_repl);
	lc_channel_join(chan_repl);

	/* (4) send packet */
	lc_msg_init_data(&msg, pkt.iov_base, pkt.iov_len, NULL, NULL);
	test_log("packed %zu bytes ready to send", data.iov_len);
	lc_msg_send(chan, &msg);
	free(pkt.iov_base);
	free(data.iov_base);

	/* (5) await reply */
	lc_msg_recv(sock_repl, &msg_repl);
	test_assert(msg_repl.len > 0, "message has nonzero length");
	test_assert(((uint8_t *)msg_repl.data)[0] == AUTH_OP_USER_UNLOCK, "opcode"); /* FIXME */
	test_assert(((uint8_t *)msg_repl.data)[1] == 0x0, "flags");

	/* (6) decrypt reply */
	test_log("decrypt reply");
	test_assert(msg_repl.len > 2, "message has payload");
	auth_payload_t reply = {0};
	struct iovec fields[1];
	reply.fields = fields;
	reply.fieldcount = 1;

	test_assert(auth_decode_packet_key(&msg_repl, &reply, sk) == 0, "decrypt server reply");
	test_log("test server reply decrypted with %i fields", reply.fieldcount);
	test_assert(reply.fields != NULL, "reply payload not NULL");
	for (int i = 0; i < reply.fieldcount; i++) {
		test_log("%.*s", (int)reply.fields[i].iov_len, (char*)reply.fields[i].iov_base);
	}
	free(reply.data);
	lc_msg_free(&msg_repl);

	/* TODO: (7) handle response/error */

	/* we finished quickly, wake the test runner */
	pthread_kill(*((pthread_t *)arg), SIGINT);
	test_log("test thread exiting");
	pthread_exit(arg);
}

void sighandler(int sig)
{
	test_log("signal caught: %i", sig);
}

void runtests(pid_t pid)
{
	struct timespec t = { 5, 0 }; /* crypto code is slow under valgrind */
	void *ret = NULL;
	struct sigaction sa = { .sa_handler = sighandler };
	sigaction(SIGINT, &sa, NULL);
	pthread_t thread;
	pthread_t self = pthread_self();
	pthread_attr_t attr = {0};
	pthread_attr_init(&attr);
	pthread_create(&thread, &attr, testthread, &self);
	nanosleep(&t, NULL); /* wait for tests to run */
	pthread_cancel(thread);
	pthread_join(thread, &ret);
	test_assert(ret != PTHREAD_CANCELED, "test thread timeout");
	kill(pid, SIGINT); /* stop server */
	lc_ctx_free(lctx);
}

int main()
{
	test_name("AUTH_OP_USER_UNLOCK - use token to set user password");
	config_include("./0000-0017.conf");
	pid_t pid = fork();
	assert (pid != -1);
	if (pid)
		runtests(pid);
	else {
		auth_init();
		close(1); /* prevent server messing up test output */
		server_start();
		auth_free();
	}
	config_free();
	return fails;
}
