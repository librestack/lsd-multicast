# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2020 Brett Sheffield <bacs@librecast.net>

INSTALLDIR=/usr/local/bin

.PHONY: all clean src test check install

all: src

install: all
	cd src && $(MAKE) $@

src:
	cd src && $(MAKE)
clean:
	cd src && $(MAKE) $@
	cd test && $(MAKE) $@
realclean:
	cd src && $(MAKE) $@
	cd test && $(MAKE) $@
check test:
	cd test && $(MAKE) $@
%.test %.check:
	cd test && $(MAKE) -B $@
