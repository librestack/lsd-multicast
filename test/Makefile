# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only
# Copyright (c) 2020 Brett Sheffield <bacs@librecast.net>

SHELL := /bin/bash
CFLAGS += -Wall -g
NOTOBJS := ../src/lsdbd.o ../src/keymgr.o
OBJS := test.o ../src/lex.yy.o ../src/y.tab.o $(filter-out $(NOTOBJS), $(wildcard ../src/*.o))
LDFLAGS := -llibrecast -llsdb -llcdb -ldl
BOLD := "\\e[0m\\e[2m"
RESET := "\\e[0m"
PASS = "\\e[0m\\e[32mOK\\e[0m" # end bold, green text
FAIL = "\\e[0m\\e[31mFAIL\\e[0m" # end bold, red text
LEAK = "\\e[0m\\e[31mFAIL \| LEAK\\e[0m\\n\\tSee $@.valgrind"
LASTLOG := lastlog.log
LOGFILE := $(shell mktemp "lsdb-test-XXXXXXXX.log")
TIMESTAMP = $(shell date +"%Y-%m-%d %H:%M:%S")
VALGRIND = valgrind --leak-check=full --error-exitcode=2 --errors-for-leak-kinds=all --track-origins=yes --log-file=$@.valgrind

.PHONY: test clean realclean build result check

check: MEMCHECK = $(VALGRIND)
check: FAIL = $(LEAK)
check: test

sanitize: CFLAGS += -fsanitize=address -fno-omit-frame-pointer
sanitize: test

test: clean build $(shell echo ????-????.c | sed 's/\.c/\.test/g') result

build:
	cd ../src && $(MAKE)
	cd ../modules && $(MAKE)
	@echo -e "$(TIMESTAMP) - starting tests" >> $(LOGFILE)
	@echo -e "\nRunning tests"

0000-0003.test: LDFLAGS += -pthread
0000-0004.test: LDFLAGS += -lwolfssl
0000-0005.test: LDFLAGS += -lsodium
0000-0007.test: LDFLAGS += -pthread
0000-0008.test: LDFLAGS += -pthread
0000-0009.test: LDFLAGS += ../modules/auth.o -lsodium -lcurl -pthread
0000-0010.test: LDFLAGS += ../modules/auth.o -lsodium -lcurl
0000-0011.test: LDFLAGS += ../modules/auth.o -lsodium -lcurl
0000-0012.test: LDFLAGS += ../modules/auth.o -lsodium -lcurl
0000-0013.test: LDFLAGS += ../modules/auth.o -lsodium -lcurl
0000-0014.test: LDFLAGS += ../modules/auth.o -lsodium -lcurl
0000-0015.test: LDFLAGS += ../modules/auth.o -lsodium -lcurl
0000-0016.test: LDFLAGS += ../modules/auth.o -lsodium -lcurl
0000-0017.test: LDFLAGS += ../modules/auth.o -lsodium -lcurl -pthread

%.test: %.c $(OBJS)
	@$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo -ne "\e[2m" $* " "
	@echo -ne "\n== $@" >> $(LOGFILE)
	@$(MEMCHECK) ./$@ 2>> $(LOGFILE) && echo -e " $(PASS)" || echo -e " $(FAIL)"
	@ln -sf $(LOGFILE) $(LASTLOG)
	@$(eval tests_run=$(shell echo $$(($(tests_run)+1))))

%.check: MEMCHECK = $(VALGRIND)
%.check: FAIL = $(LEAK)
%.check: %.test
	@echo "check completed"
	@echo -e "    logfile:   " $(BOLD) $(LOGFILE) / $(LASTLOG) $(RESET)
	@echo -e "    valgrind:  " $(BOLD) "$^.valgrind" $(RESET)

%.debug: MEMCHECK = gdb
%.debug: %.test
	@echo "exiting debugger"

test.o: test.h

result:
	@echo -e "\n$(TIMESTAMP) - tests done" >> $(LOGFILE)
	@echo -e "$(tests_run) tests run\nlogfile: $(LOGFILE)\n"

clean:
	rm -f *.test *.o
	@rm -f $(LOGFILE) $(LASTLOG)

realclean: clean
	rm -f lsdb-test-????????.log* ????-????.test.valgrind
	rm -rf ????-????.tmp.* *core*
