/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/config.h"

int main()
{
	test_name("config: protocol handlers");
	config_include("./0000-0007.conf");
	handler_t *h = config.handlers;
	test_assert(h != NULL, "config.handlers");
	test_assert(h && h->port == 4242, "handler (1) port set");
	test_expect("echo", h->channel);
	test_expect("SHA3", h->channelhash);
	test_expect("echo", h->module);
	test_expect("asdfkashefyasdfljasdkufghaskdufhasddgflkjashdfk", h->key_public);
	test_expect("isdhiwygasdikfhasfgdhlkjasdhahskjlhajshdfkajsf", h->key_private);
	h = h->next;
	test_assert(h && h->port == 1234, "handler (2) port set");
	test_assert(h && h->next == NULL, "end of handler list");
	test_expect("ff3e:f991:1bcb:2723:1658:a531:5f33:c58c", h->channel);
	test_expect("bounce", h->module);
	config_free();
	return fails;
}
