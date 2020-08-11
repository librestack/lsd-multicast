/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "echo.h"
#include "../src/log.h"
#include <stdio.h>

void init(void)
{
	config.loglevel = 127;
	DEBUG("I am the very model of a modern echo module");
}

void finit(void)
{
}

void handle_msg(lc_message_t *msg)
{
}

void handle_err(int err)
{
}
