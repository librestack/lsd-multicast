# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2020 Brett Sheffield <bacs@librecast.net>

CFLAGS += -Wall
OBJS := test.o ../src/lex.yy.o ../src/y.tab.o $(filter-out ../src/lsdbd.o, $(wildcard ../src/*.o))
LIBS := -llibrecast
PASS := "\\e[0m\\e[32m" # end bold, green text
FAIL := "\\e[0m\\e[31m" # end bold, red text
LOGFILE := $(shell mktemp)
TIMESTAMP = $(shell date +"%Y-%m-%d %H:%M:%S")

.PHONY: test clean build result memcheck

memcheck: MEMCHECK = valgrind -q --leak-check=full --error-exitcode=2 --errors-for-leak-kinds=all

memcheck: test

test: clean build $(shell echo ????-????.c | sed 's/\.c/\.test/g') result

build:
	cd ../src && $(MAKE)
	@echo -e "$(TIMESTAMP) - starting tests" >> $(LOGFILE)
	@echo -e "\nRunning tests"

%.test: %.c $(OBJS)
	@$(CC) $(CFLAGS) -o $@ $^ $(LIBS)
	@echo -ne "\e[2m" $* " "
	@echo -e "\n== $@" >> $(LOGFILE)
	@$(MEMCHECK) ./$@ 2>> $(LOGFILE) && echo -e " $(PASS)OK\e[0m" || echo -e " $(FAIL)FAIL\e[0m"
	@$(eval tests_run=$(shell echo $$(($(tests_run)+1))))

test.o: test.h

result:
	@echo -e "\n$(TIMESTAMP) - tests done" >> $(LOGFILE)
	@echo -e "$(tests_run) tests run\nlogfile: $(LOGFILE)\n"

clean:
	rm -f *.test *.o
