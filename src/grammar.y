/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

%{
#include <stdio.h>
#include <string.h>
#include "config.h"
#include "y.tab.h"
extern int lineno;
void yyerror(const char *str);
int yylex();
int yywrap();

%}
%union
{
	int ival;
	char *sval;
}
%token <ival> BOOL
%token <sval> CERT
%token <sval> CHANNEL
%token <sval> COLON
%token <sval> COMMENT
%token <ival> DAEMON
%token <sval> DBLQUOTE
%token <sval> DBLQUOTEDSTRING
%token <ival> DEBUGMODE
%token <sval> FILENAME
%token <sval> KEY
%token <ival> LOGLEVEL
%token <sval> NEWLINE
%token <ival> NUMBER
%token <sval> PROTO
%token <sval> SLASH
%token <sval> WORD
%token <sval> V6ADDR

%%
configs:
	/* empty */
	| configs config
	;

config:
	COMMENT
	{ /* skip comment */ }
	|
	CHANNEL DBLQUOTEDSTRING
	{
		fprintf(stderr, "joining channel '%s'\n", $2);
	}
	|
	CHANNEL WORD
	{
		fprintf(stderr, "joining channel '%s'\n", $2);
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
	;
%%
void yyerror(const char *str)
{
	fprintf(stderr,"error on line %i: %s\n", lineno, str);
}

int yywrap()
{
	return 1;
}
