/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/server.h"

int main()
{
	test_name("start server");

	server_start();
	server_stop();

	return fails;
}
