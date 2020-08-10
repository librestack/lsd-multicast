/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/config.h"
#include "../src/server.h"
#include "../src/wire.h"
#include <librecast.h>
#include <time.h>
#include <unistd.h>

int main()
{
	test_name("config: protocol handlers");
	config_include("./0000-0007.conf");

	handler_t *h = config.handlers;

	test_assert(h != NULL, "config.handlers");
	test_assert(h && h->port == 4242, "handler (1) port set");
	test_assert(h && h->next && h->next->port == 1234, "handler (2) port set");
	test_assert(h && h->next && h->next->next == NULL, "end of handler list");

	config_free();
	return fails;
}
