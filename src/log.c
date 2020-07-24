/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2012-2020 Brett Sheffield <bacs@librecast.net> */

#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include "config.h"
#include "log.h"

#define LOG_BUFSIZE 128

void logmsg(unsigned int level, const char *fmt, ...)
{
	va_list argp;
	char *mbuf = NULL;
	char buf[LOG_BUFSIZE];
	char *b = buf;
	int len;

	if ((level & config.loglevel) != level) return;

	va_start(argp, fmt);
	len = vsnprintf(buf, LOG_BUFSIZE, fmt, argp);
	if (len > LOG_BUFSIZE) {
		/* need a bigger buffer, resort to malloc */
		mbuf = malloc(len + 1);
		va_end(argp);
		va_start(argp, fmt);
		vsprintf(mbuf, fmt, argp);
		b = mbuf;
	}
	va_end(argp);
	if (level == LOG_INFO)
		fprintf(stdout, "%s\n", b);
	else
		fprintf(stderr, "%s\n", b);
	free(mbuf);
}
