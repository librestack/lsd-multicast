/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#ifndef _LSDBD_AUTH_H
#define _LSDBD_AUTH_H 1

#include <errno.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/types.h>

typedef struct authpkt_s authpkt_t;
struct authpkt_s {
	struct iovec repl;
	struct iovec user;
	struct iovec mail;
	struct iovec pass;
	struct iovec serv;
};

ssize_t auth_pack(struct iovec *data, struct iovec *repl,
		  struct iovec *user, struct iovec *mail,
		  struct iovec *pass, struct iovec *serv);

size_t	auth_unpack(authpkt_t *pkt, void *data, size_t len);

#endif /* _LSDBD_AUTH_H */
