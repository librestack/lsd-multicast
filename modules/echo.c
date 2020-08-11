/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "echo.h"
#include "../src/log.h"
#include <stdio.h>

void init(void)
{
	TRACE("echo.so %s()", __func__);
	config.loglevel = 127;
	DEBUG("I am the very model of a modern echo module");
}

void finit(void)
{
	TRACE("echo.so %s()", __func__);
}

void handle_msg(lc_message_t *msg)
{
	TRACE("echo.so %s()", __func__);
	DEBUG("I have received the message");

	/* TODO:
	 * - decrypt
	 * - call opcode handler
	 * - unpack
	 */
	DEBUG("message says '%.*s'", (int)msg->len, (char *)msg->data);
}

void handle_err(int err)
{
	TRACE("echo.so %s()", __func__);
	DEBUG("handle_err() err=%i", err);
}
