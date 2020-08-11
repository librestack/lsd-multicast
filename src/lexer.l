/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

%{
#include <stdio.h>
#include "y.tab.h"
int lineno = 1;
%}

%%
\}				return BRACECLOSE;
\{				return BRACEOPEN;
\)				return BRACKETCLOSE;
\(				return BRACKETOPEN;
cert				return CERT;
channel				return CHANNEL;
daemon				return DAEMON;
debug				return DEBUGMODE;
false|true			yylval.ival = strcmp(yytext, "false"); return BOOL;
handler				return HANDLER;
key				return KEY;
key_priv			return KEYPRIV;
key_pub				return KEYPUB;
loglevel			return LOGLEVEL;
modpath				return MODPATH;
module				return MODULE;
port				return PORT;
proto				return PROTO;
scope				return SCOPE;
[0-9]+				yylval.ival = atoi(yytext); return NUMBER;
:				return COLON;
\"[^"\n]*["\n] {
	yylval.sval = strdup(yytext + 1);
	if (yylval.sval[yyleng - 2] != '"')
		fprintf(stderr, "double quoted string not closed\n");
	else
		yylval.sval[yyleng-2] = 0;
	return DBLQUOTEDSTRING;
}

[a-f0-9\:]+			yylval.sval=strdup(yytext); return V6ADDR;
\/				return SLASH;
[a-zA-Z0-9]+			yylval.sval=strdup(yytext); return WORD;
[a-zA-Z0-9.\-\/]+		yylval.sval=strdup(yytext); return FILENAME;
\n				{ ++lineno; /* ignore newline */ }
[ \t]+				/* ignore whitespace */;
\#[^\n]*			return COMMENT;
%%
