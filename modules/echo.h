/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#ifndef _LSDM_ECHO_H
#define _LSDM_ECHO_H 1

#include <librecast.h>

void init(void);
void finit(void);
void handle_msg(lc_message_t *msg);
void handle_err(int err);

#endif /* _LSDM_ECHO_H */
