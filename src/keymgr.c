/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include <sodium.h>
#include <stdio.h>

int main(int argc, char **argv)
{
	unsigned char pk[crypto_box_PUBLICKEYBYTES];
	unsigned char sk[crypto_box_SECRETKEYBYTES];
	const size_t pkhexlen = crypto_box_PUBLICKEYBYTES * 2 + 1;
	const size_t skhexlen = crypto_box_SECRETKEYBYTES * 2 + 1;
	char pkhex[pkhexlen];
	char skhex[skhexlen];

	if (sodium_init() == -1) {
		return 1;
	}
	printf("generating keypair... ");
	crypto_box_keypair(pk, sk);
	printf("done\n");

	sodium_bin2hex(pkhex, pkhexlen, pk, crypto_box_PUBLICKEYBYTES);
	sodium_bin2hex(skhex, skhexlen, sk, crypto_box_SECRETKEYBYTES);
	printf("public key: %s\n", pkhex);
	printf("secret key: %s\n", skhex);

	return 0;
}
