/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#ifndef _LSDBD_AUTH_H
#define _LSDBD_AUTH_H 1

#include <errno.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/types.h>

/* Ok, we need a flexible, extensible binary protocol
 *
 * [opcode][flags][fields...]
 * opcode determines how packet will be handled and which fields to expect
 *
 * fields will be assigned via bitmasks to opcodes which use them
 *
 * each field will be [size][data]
 * where size is a char (8 bits) if all bits are set, size overflows to the next
 * byte, allowing for extensible sizes up to any limit we require
 * 
 * opcode and flags will use half a byte each and can also overflow
 * if opcode overflows to a whole byte or more, flags becomes a whole byte
 * minimum */

#define AUTH_OPCODES(X) \
	X(0x0, AUTH_OP_NOOP,		"NOOP",		auth_op_noop) \
	X(0x1, AUTH_OP_USER_ADD,	"USER_ADD",	auth_op_user_add) \
	X(0x2, AUTH_OP_USER_DEL,	"USER_DEL",	auth_op_user_delete) \
	X(0x3, AUTH_OP_USER_LOCK,	"USER_LOCK",	auth_op_user_lock) \
	X(0x4, AUTH_OP_USER_UNLOCK,	"USER_UNLOCK",	auth_op_user_unlock) \
	X(0x5, AUTH_OP_KEY_ADD,		"KEY_ADD",	auth_op_key_add) \
	X(0x6, AUTH_OP_KEY_DEL,		"KEY_DEL",	auth_op_key_delete) \
	X(0x7, AUTH_OP_KEY_REP,		"KEY_REP",	auth_op_key_replace) \
	X(0x8, AUTH_OP_AUTH_SERV,	"AUTH_SERV",	auth_op_auth_service)
#undef X

#define AUTH_OPCODE_ENUM(code, name, text, f) name = code,
typedef enum {
        AUTH_OPCODES(AUTH_OPCODE_ENUM)
} auth_opcode_t;

#define AUTH_FLD_REPL		0x1
#define AUTH_FLD_USER		0x2
#define AUTH_FLD_MAIL		0x4
#define AUTH_FLD_PASS		0x8
#define AUTH_FLD_SERV		0x16
#define AUTH_FLD_KEY		0x32

/* map fields to opcodes with bitmask */
#define AUTH_OP_USER_ADD	AUTH_FLD_REPL | AUTH_FLD_USER | AUTH_FLD_MAIL | AUTH_FLD_PASS | AUTH_FLD_SERV

enum {
	AUTH_REPL,
	AUTH_USER,
	AUTH_MAIL,
	AUTH_PASS,
	AUTH_SERV
};

typedef struct authpkt_s authpkt_t;
struct authpkt_s {
	struct iovec repl;
	struct iovec user;
	struct iovec mail;
	struct iovec pass;
	struct iovec serv;
};

ssize_t auth_pack(struct iovec *data, struct iovec *iovs[], int iov_count);
size_t	auth_unpack(authpkt_t *pkt, void *data);

#endif /* _LSDBD_AUTH_H */
