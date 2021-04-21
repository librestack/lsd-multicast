/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../modules/auth.h"
#include "../src/config.h"
#include "../src/server.h"
#include "../src/wire.h"
#include <assert.h>
#include <librecast.h>
#include <signal.h>
#include <sodium.h>
#include <unistd.h>

void runtests()
{
	lc_message_t msg;
	struct iovec data = {0};
	handler_t *h = config.handlers;
	test_assert(h != NULL, "handlers");

	/* generate keypair & use as reply address */
	unsigned char pk[crypto_box_PUBLICKEYBYTES];
	unsigned char sk[crypto_box_SECRETKEYBYTES];
	test_assert(sodium_init() != -1, "sodium_init()");
	test_assert(crypto_box_keypair(pk, sk) != -1, "crypto_box_keypair()");

	/* build packet */
	struct iovec repl = { .iov_base = pk, .iov_len = crypto_box_PUBLICKEYBYTES };
	struct iovec user = { .iov_base = "username" };
	struct iovec mail = { .iov_base = "noreply@librecast.net" };
	struct iovec pass = { .iov_base = "password" };
	struct iovec serv = { .iov_base = "service" };
	struct iovec *iovs[] = { &repl, &user, &mail, &pass, &serv };
	const int iov_count = sizeof iovs / sizeof iovs[0];
	uint8_t op = AUTH_OP_USER_ADD;
	uint8_t flags = 9;
	ssize_t len;
	for (int i = 1; i < iov_count; i++) {
		iovs[i]->iov_len = strlen(iovs[i]->iov_base);
	}
	len = wire_pack_pre(&data, *iovs, iov_count, NULL, 0);
	test_assert(len > 0, "wire_pack_pre() returned %i", len);

	/* encrypt packet */
	char *authpubhex = h->key_public;
	unsigned char authpubkey[crypto_box_PUBLICKEYBYTES];
	unsigned char nonce[crypto_box_NONCEBYTES];
	const size_t cipherlen = crypto_box_MACBYTES + data.iov_len;
	unsigned char ciphertext[cipherlen];
	auth_key_crypt_pk_bin(authpubkey, authpubhex);
	randombytes_buf(nonce, sizeof nonce);
	test_assert(!crypto_box_easy(ciphertext, (unsigned char *)data.iov_base, data.iov_len, nonce, authpubkey, sk), "crypto_box_easy()");

	/* now pack encrypted payload with public key and nonce prepended */
	struct iovec iovkey = { .iov_base = pk, .iov_len = crypto_box_PUBLICKEYBYTES };
	struct iovec iovnon = { .iov_base = nonce, .iov_len = crypto_box_NONCEBYTES };
	struct iovec crypted = { .iov_base = ciphertext, .iov_len = cipherlen };
	struct iovec payload[] = { iovkey, iovnon, crypted };
	struct iovec pkt = {0};
	len = wire_pack(&pkt, payload, 3, op, flags);

	lc_msg_init_data(&msg, pkt.iov_base, pkt.iov_len, NULL, NULL);

	auth_payload_t p = {0};
	struct iovec fields[iov_count];
	p.fields = fields;
	p.fieldcount = iov_count;
	test_assert(auth_decode_packet(&msg, &p) == 0, "auth_decode_packet()");
	/* verify every field matches what we packed */
	for (int i = 0; i < p.fieldcount; i++) {
		test_expectiov(iovs[i], &fields[i]);
	}
	free(p.data);
	free(pkt.iov_base);
	free(data.iov_base);
}

int main()
{
	test_name("auth_decode_packet()");
	config_include("./0000-0012.conf");
	runtests();
	config_free();
	return fails;
}
