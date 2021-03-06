# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only
# Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net>

CFLAGS := -Wall -Wextra -Wpedantic -g
export CFLAGS
INSTALLDIR := /usr/local/bin
export INSTALLDIR
PROGRAM := lsdbd
export PROGRAM
COVERITY_DIR := cov-int
COVERITY_TGZ := $(PROGRAM).tgz

.PHONY: all clean src modules test check install

all: src modules

install: all
	cd src && $(MAKE) $@

src:
	$(MAKE) -C $@

modules:
	$(MAKE) -B -C $@

clean realclean:
	cd src && $(MAKE) $@
	cd modules && $(MAKE) $@
	cd test && $(MAKE) $@
	rm -rf ./$(COVERITY_DIR)
	rm -f $(COVERITY_TGZ)

sparse: clean
	CC=cgcc $(MAKE) src

check test sanitize: src
	cd test && $(MAKE) $@

%.test %.check: modules
	cd test && $(MAKE) -B $@

coverity: clean
	PATH=$(PATH):../cov-analysis-linux64-2019.03/bin/ cov-build --dir cov-int $(MAKE) src
	tar czvf $(COVERITY_TGZ) $(COVERITY_DIR)
