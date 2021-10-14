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
	$(MAKE) -C $@

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

%.test %.check: src
	cd test && $(MAKE) $@

coverity: clean
	PATH=$(PATH):../cov-analysis-linux64-2019.03/bin/ cov-build --dir cov-int $(MAKE) src
	tar czvf $(COVERITY_TGZ) $(COVERITY_DIR)

net-setup:
	ip link add veth0 type veth peer name veth1
	ip netns add vnet0
	ip netns add vnet1
	ip link set veth0 netns vnet0
	ip link set veth1 netns vnet1
	ip -n vnet0 link set veth0 up
	ip -n vnet1 link set veth1 up
	ip netns show

net-teardown:
	ip -n vnet0 link set veth0 down
	ip -n vnet1 link set veth1 down
	ip -n vnet1 link set veth1 netns vnet0
	ip -n vnet0 link del veth0 type veth peer name veth1
	ip netns del vnet0
	ip netns del vnet1
	ip netns show
