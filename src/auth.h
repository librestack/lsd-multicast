/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#ifndef _LSDBD_AUTH_H
#define _LSDBD_AUTH_H 1

#include <errno.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/types.h>

typedef struct authpkt_s authpkt_t;

/* fixed width */
struct authpkt_s {
	char 	username[36];	/* uuid */
	char 	email[256];	/* RFC 5321 */
	char 	password[256];
	char 	service[64];
};

ssize_t auth_pack(struct iovec *username, struct iovec *email,
		  struct iovec *password, struct iovec *service);

#endif /* _LSDBD_AUTH_H */
