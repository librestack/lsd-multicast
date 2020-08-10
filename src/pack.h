/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#ifndef _LSDM_PACK_H
#define _LSDM_PACK_H 1

#include <errno.h>
//#include <limits.h>
#include <stdint.h>
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

ssize_t pack_data(struct iovec *data, struct iovec *iovs[], int iov_count, uint8_t op, uint8_t flags);
ssize_t unpack_data(struct iovec *data, struct iovec iovs[], int iov_count, uint8_t *op, uint8_t *flags);

#endif /* _LSDM_PACK_H */
