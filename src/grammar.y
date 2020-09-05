/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

%{
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include "config.h"
#include "y.tab.h"
extern int lineno;
void yyerror(const char *str);
int yylex(void);
int yywrap(void);
int handlers = 0;
handler_t *handler_last;
handler_t handler = {
	.token_duration = 360
};

%}
%union
{
	int ival;
	char *sval;
}
%token <sval> BRACECLOSE
%token <sval> BRACEOPEN
%token <sval> BRACKETCLOSE
%token <sval> BRACKETOPEN
%token <ival> BOOL
%token <sval> CERT
%token <sval> CHANNEL
%token <sval> COLON
%token <sval> COMMENT
%token <ival> DAEMON
%token <sval> DBNAME
%token <sval> DBPATH
%token <sval> DBLQUOTE
%token <sval> DBLQUOTEDSTRING
%token <ival> DEBUGMODE
%token <sval> FILENAME
%token <sval> HANDLER
%token <sval> KEY
%token <sval> KEYPRIV
%token <sval> KEYPUB
%token <ival> LOGLEVEL
%token <sval> MODPATH
%token <sval> MODULE
%token <sval> NEWLINE
%token <ival> NUMBER
%token <ival> PORT
%token <sval> PROTO
%token <sval> SCOPE
%token <sval> SECTION
%token <sval> SLASH
%token <sval> TESTMODE
%token <ival> TOKEN_DURATION
%token <sval> WORD
%token <sval> V6ADDR

%%
globals:
	/* empty */
	| globals global
	;

global:
	COMMENT { /* skip comment */ }
	|
	HANDLER BRACEOPEN handlers BRACECLOSE
	{
		fprintf(stderr, "handler %i\n", ++handlers);
		handler_t *h = malloc(sizeof(handler_t));
		if (!config.handlers)
			config.handlers = h;
		else
			handler_last->next = h;
		memcpy(h, &handler, sizeof(handler_t));
		handler_last = h;
		memset(&handler, 0, sizeof(handler_t));
	}
	|
	DAEMON BOOL
	{
		if ($2) {
			fprintf(stderr, "daemonizing\n");
			config.daemon = 1;
		}
	}
	|
	DEBUGMODE BOOL
	{
		if ($2) {
			config.debug = 1;
			fprintf(stderr, "debug mode enabled\n");
		}
	}
	|
	TESTMODE BOOL
	{
		if ($2) {
			config.testmode = 1;
			fprintf(stderr, "test mode enabled\n");
		}
	}
	|
	LOGLEVEL NUMBER
	{
		fprintf(stderr, "loglevel set to %i\n", $2);
		config.loglevel = $2;
	}
	|
	KEY FILENAME
	{
		fprintf(stderr, "key = '%s'\n", $2);
		config.key = $2;
	}
	|
	CERT FILENAME
	{
		fprintf(stderr, "cert = '%s'\n", $2);
		config.cert = $2;
	}
	|
	MODPATH FILENAME
	{
		fprintf(stderr, "modpath = '%s'\n", $2);
		config.modpath = $2;
	}
	;

handlers:
	/* this space intentionally left blank */
	| handlers handler
	;

handler:
	COMMENT { /* skip comment */ }
	|
	CHANNEL	WORD BRACKETOPEN DBLQUOTEDSTRING BRACKETCLOSE
	{
		fprintf(stderr, "handler channel = %s(\"%s\")\n", $2, $4);
		handler.channelhash = $2;
		handler.channel = $4;
	}
	|
	CHANNEL	V6ADDR
	{
		fprintf(stderr, "handler channel = %s\n", $2);
		handler.channelhash = NULL;
		handler.channel = $2;
	}
	|
	DBNAME DBLQUOTEDSTRING
	{
		fprintf(stderr, "handler dbname = '%s'\n", $2);
		handler.dbname = $2;
	}
	|
	DBPATH FILENAME
	{
		fprintf(stderr, "handler dbpath = '%s'\n", $2);
		handler.dbpath = $2;
	}
	|
	KEYPRIV WORD
	{
		fprintf(stderr, "handler private key = %s\n", $2);
		handler.key_private = $2;
	}
	|
	KEYPUB WORD
	{
		fprintf(stderr, "handler public key = %s\n", $2);
		handler.key_public = $2;
	}
	|
	MODULE FILENAME
	{
		fprintf(stderr, "handler module = %s\n", $2);
		handler.module = $2;
		config.modules++;
	}
	|
	MODULE WORD
	{
		fprintf(stderr, "handler module = %s\n", $2);
		handler.module = $2;
		config.modules++;
	}
	|
	PORT NUMBER
	{
		fprintf(stderr, "handler port = %i\n", $2);
		if ($2 < 0 || $2 > UINT16_MAX)
			fprintf(stderr, "invalid handler port on line: %i\n", lineno);
		else
			handler.port = $2;
	}
	|
	SCOPE WORD
	{
		fprintf(stderr, "handler scope = %s\n", $2);
		handler.scope = $2;
	}
	|
	TOKEN_DURATION NUMBER
	{
		fprintf(stderr, "token_duration = %i\n", $2);
		handler.token_duration = $2;
	}
	;
%%
void yyerror(const char *str)
{
	fprintf(stderr,"error on line %i: %s\n", lineno, str);
}

int yywrap(void)
{
	return 1;
}
