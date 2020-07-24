# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2020 Brett Sheffield <bacs@librecast.net>

PROGRAM = lsdbd
CFLAGS += -Wall -g
OBJS = lex.yy.o y.tab.o config.o $(PROGRAM).o

$(PROGRAM): $(OBJS)
	$(CC) $(OBJS) -o $@ -llibrecast

$(PROGRAM).o:	$(PROGRAM).h

config.o: config.h

lex.yy.o:

y.tab.o: y.tab.h

y.tab.h: grammar.y
	$(YACC) -d $^

y.tab.c: grammar.y
	$(YACC) $^

lex.yy.c: lexer.l y.tab.h
	$(LEX) lexer.l

.PHONY: clean

clean:
	rm -f y.tab.c y.tab.h lex.yy.c *.o $(PROGRAM)
