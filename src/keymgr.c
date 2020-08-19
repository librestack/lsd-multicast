/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include <sodium.h>
#include <stdio.h>

int main(int argc, char **argv)
{
	unsigned char pk_sign[crypto_sign_PUBLICKEYBYTES];
	unsigned char sk_sign[crypto_sign_SECRETKEYBYTES];
	unsigned char pk_box[crypto_box_PUBLICKEYBYTES];
	unsigned char sk_box[crypto_box_SECRETKEYBYTES];
	const size_t pk_signhexlen = crypto_sign_PUBLICKEYBYTES * 2 + 1;
	const size_t sk_signhexlen = crypto_sign_SECRETKEYBYTES * 2 + 1;
	const size_t pk_boxhexlen = crypto_box_PUBLICKEYBYTES * 2 + 1;
	const size_t sk_boxhexlen = crypto_box_SECRETKEYBYTES * 2 + 1;
	char pk_signhex[pk_signhexlen];
	char sk_signhex[sk_signhexlen];
	char pk_boxhex[pk_boxhexlen];
	char sk_boxhex[sk_boxhexlen];

	if (sodium_init() == -1) {
		return 1;
	}
	printf("generating keypairs... ");
	crypto_box_keypair(pk_box, sk_box);
	crypto_sign_keypair(pk_sign, sk_sign);
	printf("done\n");

	sodium_bin2hex(pk_signhex, pk_signhexlen, pk_sign, crypto_sign_PUBLICKEYBYTES);
	sodium_bin2hex(sk_signhex, sk_signhexlen, sk_sign, crypto_sign_SECRETKEYBYTES);
	sodium_bin2hex(pk_boxhex, pk_boxhexlen, pk_box, crypto_box_PUBLICKEYBYTES);
	sodium_bin2hex(sk_boxhex, sk_boxhexlen, sk_box, crypto_box_SECRETKEYBYTES);
	printf("key_pub		%s%s\n", pk_boxhex, pk_signhex);
	printf("key_priv	%s%s\n", sk_boxhex, sk_signhex);

	return 0;
}
