# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2020 Brett Sheffield <bacs@librecast.net>

CFLAGS += -Wall -g -shared -fPIC
MODULES := echo.so auth.so
NOTOBJS := ../src/lsdbd.o ../src/keymgr.o
COMMON_OBJECTS := ../src/lex.yy.o ../src/y.tab.o $(filter-out $(NOTOBJS), $(wildcard ../src/*.o))
LIBS := -lsodium

all: $(MODULES)

auth.so: auth.o $(COMMON_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS) -lcurl

echo.so: echo.o $(COMMON_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

%.o: %.h

.PHONY: clean

clean:
	rm -f *.o $(MODULES)

realclean: clean
