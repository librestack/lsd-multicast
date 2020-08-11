# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2020 Brett Sheffield <bacs@librecast.net>

CFLAGS += -Wall -g
OBJS := 
MODULES := echo.so
COMMON_OBJECTS := ../src/wire.o

all: $(MODULES)

echo.so:        echo.o $(COMMON_OBJECTS)
	$(CC) -shared -fPIC -o $@  $^

echo.o:		echo.h

.PHONY: clean

clean:
	rm -f *.o $(MODULES)

realclean: clean
