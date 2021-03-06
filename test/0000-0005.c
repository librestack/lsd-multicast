/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/config.h"
#include "../src/server.h"
#include <librecast/net.h>
#include <librecast/db.h>
#include <time.h>
#include <unistd.h>
#include <sodium.h>

#define HASHSIZE crypto_generichash_BYTES

void logtime(char *msg)
{
	time_t t;
	struct tm *tmp;
	char tstr[128];
	t = time(NULL);
	tmp = localtime(&t);
	strftime(tstr, sizeof(tstr), "%X", tmp);
	test_log("%s - %s", tstr, msg);
}

unsigned char * hash(unsigned char digest[HASHSIZE], char *data, size_t len)
{
	crypto_generichash(digest, HASHSIZE, (unsigned char *)data, len, NULL, 0);
	return digest;
}

int main()
{
	char dbpath[] = "0000-0005.tmp.XXXXXX";
	lc_ctx_t *lctx = NULL;
	lc_db_t *lcdb = NULL;
	char db[] = "hashmap";
	const int limit = 1000000;
	unsigned char key[HASHSIZE];
	char data[4];
	void *vptr;
	size_t vlen;
	int ret;

	return test_skip("write %i hash keys (BLAKE2) to lmdb", limit);
	config.debug = 1;
	config.loglevel = 79;
	lctx = lc_ctx_new();
	test_assert (sodium_init() >= 0, "libsodium initialized");
	lcdb = lc_db_open(lctx, mkdtemp(dbpath));
	test_assert(lcdb != NULL, "lc_db_open() - open temp db");
	logtime("starting write");
	for (int i = 1; i <= limit; i++) {
		snprintf(data, sizeof(data), "%i", i);
		hash(key, data, strlen(data));
		ret = lc_db_set(lcdb, db, key, HASHSIZE, data, strlen(data));
		test_assert(ret == 0, "pass: %i written", i);
	}
	logtime("done");
	logtime("starting read");
	for (int i = 1; i <= limit; i++) {
		snprintf(data, sizeof(data), "%i", i);
		hash(key, data, strlen(data));
		ret = lc_db_get(lcdb, db, key, HASHSIZE, &vptr, &vlen);
		if (ret) test_log("lc_db_get() returned %i", ret);
		test_assert(ret == 0, "pass: %i read", i);
		test_expectn(data, (char *)vptr, vlen);
	}
	logtime("done");
	lc_db_free(lcdb);
	lc_ctx_free(lctx);

	return fails;
}
