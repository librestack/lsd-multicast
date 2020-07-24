/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

%{
#include <stdio.h>
#include "y.tab.h"
int lineno = 1;
%}

%%
cert				return CERT;
daemon				return DAEMON;
debug				return DEBUGMODE;
false|true			yylval.ival = strcmp(yytext, "false"); return BOOL;
key				return KEY;
loglevel			return LOGLEVEL;
proto				return PROTO;
\#[^\n]*			return COMMENT;
[0-9]+				yylval.ival = atoi(yytext); return NUMBER;
:				return COLON;
[a-f0-9\:]+			return V6ADDR;
\/				return SLASH;
[a-zA-Z0-9]+			return WORD;
[a-zA-Z0-9.\-\/]+		yylval.sval=strdup(yytext); return FILENAME;
\n				{ ++lineno; /* ignore newline */ }
[ \t]+				/* ignore whitespace */;
%%
