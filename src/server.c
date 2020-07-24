/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include <librecast.h>
#include "config.h"
#include "log.h"
#include "server.h"

lc_ctx_t *lctx;

void server_stop()
{
	lc_ctx_free(lctx);
}

int server_start()
{
	lctx = lc_ctx_new();
	return 0;
}
