/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

%option noinput
%option nounput
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
dbname				return DBNAME;
dbpath				return DBPATH;
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
testmode			return TESTMODE;
token_duration			return TOKEN_DURATION;
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

\/				return SLASH;
[a-zA-Z0-9]+			yylval.sval=strdup(yytext); return WORD;
[a-f0-9\:]+			yylval.sval=strdup(yytext); return V6ADDR;
[a-zA-Z0-9.\-\/]+		yylval.sval=strdup(yytext); return FILENAME;
\n				{ ++lineno; /* ignore newline */ }
[ \t]+				/* ignore whitespace */;
\#[^\n]*			return COMMENT;
%%
