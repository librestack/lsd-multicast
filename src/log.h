/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2012-2020 Brett Sheffield <bacs@librecast.net> */

#ifndef _LIBRESTACK_LOG
#define _LIBRESTACK_LOG 1

#include "config.h"

#define LOG_LEVELS(X) \
	X(0,    LOG_NONE,       "none")                                 \
	X(1,    LOG_SEVERE,     "severe")                               \
	X(2,    LOG_ERROR,      "error")                                \
	X(4,    LOG_WARNING,    "warning")                              \
	X(8,    LOG_INFO,       "info")                                 \
	X(16,   LOG_TRACE,      "trace")                                \
	X(32,   LOG_FULLTRACE,  "fulltrace")                            \
	X(64,   LOG_DEBUG,      "debug")

#define LOG_ENUM(id, name, desc) name = id,
enum {
	LOG_LEVELS(LOG_ENUM)
};
#undef LOG_LEVELS
#undef LOG_ENUM

#define LOG_LOGLEVEL_DEFAULT 15

#define FMTV(iov) (int)(iov).iov_len, (const char *)(iov).iov_base
#define FMTP(iov) (int)(iov)->iov_len, (const char *)(iov)->iov_base
#define LOG(lvl, fmt, ...) if ((lvl & config.loglevel) == lvl) logmsg(lvl, fmt ,##__VA_ARGS__)
#define BREAK(lvl, fmt, ...) {LOG(lvl, fmt ,##__VA_ARGS__); break;}
#define CONTINUE(lvl, fmt, ...) {LOG(lvl, fmt ,##__VA_ARGS__); continue;}
#define DIE(fmt, ...) {LOG(LOG_SEVERE, fmt ,##__VA_ARGS__);  _exit(EXIT_FAILURE);}
#define DEBUG(fmt, ...) LOG(LOG_DEBUG, fmt ,##__VA_ARGS__)
#define ERROR(fmt, ...) LOG(LOG_ERROR, fmt ,##__VA_ARGS__)
#define ERRMSG(err) {LOG(LOG_ERROR, err_msg(err));}
#define FAIL(err) {LOG(LOG_ERROR, err_msg(err));  return err;}
#define FAILMSG(err, fmt, ...) {LOG(LOG_ERROR, fmt ,##__VA_ARGS__);  return err;}
#define INFO(fmt, ...) LOG(LOG_INFO, fmt ,##__VA_ARGS__)
#define TRACE(fmt, ...) LOG(LOG_TRACE, fmt ,##__VA_ARGS__)

void logmsg(unsigned int level, const char *fmt, ...)
#ifdef __GNUC__
	__attribute__((format(printf, 2 ,3)))
#endif
;

#endif /* _LIBRESTACK_LOG */
