/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#ifndef _LSDBD_AUTH_H
#define _LSDBD_AUTH_H 1

#include <errno.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/types.h>

ssize_t auth_pack(struct iovec *data, struct iovec *repl,
		  struct iovec *user, struct iovec *mail,
		  struct iovec *pass, struct iovec *serv);

#endif /* _LSDBD_AUTH_H */
