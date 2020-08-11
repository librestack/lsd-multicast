# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2020 Brett Sheffield <bacs@librecast.net>

CFLAGS += -Wall -g -shared -fPIC
MODULES := echo.so auth.so
#COMMON_OBJECTS := ../src/config.o ../src/log.o ../src/wire.o
COMMON_OBJECTS := ../src/lex.yy.o ../src/y.tab.o $(filter-out ../src/lsdbd.o, $(wildcard ../src/*.o))

all: $(MODULES)

%.so: %.o $(COMMON_OBJECTS)
	$(CC) $(CFLAGS) -o $@  $^

%.o: %.h

.PHONY: clean

clean:
	rm -f *.o $(MODULES)

realclean: clean
