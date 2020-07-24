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
%token <sval> COLON
%token <sval> COMMENT
%token <ival> DAEMON
%token <ival> DEBUG
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
	DAEMON BOOL
	{
		if ($2)
			fprintf(stderr, "daemonizing\n");
		else
			fprintf(stderr, "no daemon for you\n");
	}
	|
	DEBUG BOOL
	{
		if ($2) {
			config.debug = ($2) ? 1 : 0;
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
		config.key = $2;
		fprintf(stderr, "key is '%s'\n", config.key);
	}
	|
	PROTO WORD NUMBER SLASH WORD V6ADDR
	|
	PROTO WORD NUMBER SLASH WORD
	|
	PROTO WORD NUMBER
	|
	PROTO WORD
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
