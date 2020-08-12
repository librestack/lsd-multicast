/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../modules/auth.h"
#include "../src/config.h"
#include "../src/server.h"
#include "../src/wire.h"
#include <assert.h>
#include <librecast.h>
#include <signal.h>
#include <unistd.h>

void runtests(pid_t pid)
{
	lc_ctx_t *lctx;
	lc_socket_t *sock, *sock_repl;
	lc_channel_t *chan, *chan_repl;
	lc_message_t msg, msg_repl;
	char replychannel[] = "repl";
	int opt = 1;
	struct iovec data;
	struct iovec repl = { .iov_base = replychannel };
	struct iovec user = { .iov_base = "uuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu" };
	struct iovec mail = { .iov_base = "email" };
	struct iovec pass = { .iov_base = "password" };
	struct iovec serv = { .iov_base = "service" };
	struct iovec *iovs[] = { &repl, &user, &mail, &pass, &serv };
	//struct iovec iovc[5] = {};
	const int iov_count = sizeof iovs / sizeof iovs[0];
	uint8_t op = AUTH_OP_USER_ADD;
	uint8_t flags = 7;
	size_t len;

	test_assert((len = wire_pack(&data, iovs, iov_count, op, flags)) > 0, "pack some data");
	test_log("******************* len = %zu", len);
	test_log("******************* data.iov_len = %zu", data.iov_len);

	lctx = lc_ctx_new();
	sock = lc_socket_new(lctx);
	sock_repl = lc_socket_new(lctx);
	lc_socket_setopt(sock, IPV6_MULTICAST_LOOP, &opt, sizeof(opt));
	chan = lc_channel_new(lctx, config.handlers->channel);
	//chan_repl = lc_channel_new(lctx, repl.iov_base);
	chan_repl = lc_channel_new(lctx, "repl");

	test_log("test 0000-0008 binding socket");
	lc_channel_bind(sock, chan);
	lc_channel_bind(sock_repl, chan_repl);
	//lc_channel_join(chan_repl);

	lc_msg_init_data(&msg, data.iov_base, data.iov_len, NULL, NULL);
	test_log("packed %zu bytes ready to send", data.iov_len);
	test_sleep(0, 999999); /* give server a chance to be ready */
	lc_msg_send(chan, &msg);
	test_sleep(0, 99999999); /* give server a chance to be ready */
	//lc_msg_recv(sock, &msg_repl);

	/* TODO: read and verify reply */
	//test_assert(msg_repl.len > 0, "message has nonzero length");

	lc_ctx_free(lctx);
	kill(pid, SIGINT); /* stop server */
}

int main()
{
	test_name("auth handler test (forking)");
	config_include("./0000-0009.conf");
	pid_t pid = fork();
	assert (pid != -1);
	if (pid)
		runtests(pid);
	else {
		assert(server_start() == 0);
		close(1); /* prevent server messing up test output */
	}
	config_free();
	return fails;
}
