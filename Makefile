# SPDX-License-Identifier: GPL-2.0-or-later WITH SANE-exception
# Copyright (C) 2026 Evan McClain

PREFIX ?= /usr
LIBDIR ?= $(PREFIX)/lib64
SYSCONFDIR ?= /etc
UDEVDIR ?= $(PREFIX)/lib/udev/rules.d
DESTDIR ?=

CFLAGS ?= -O2 -g
override CFLAGS += -Wall -Wextra -Wno-unused-parameter -fPIC -std=gnu11
USB_CFLAGS := $(shell pkg-config --cflags libusb-1.0)
USB_LIBS := $(shell pkg-config --libs libusb-1.0)
SANE_CFLAGS := $(shell pkg-config --cflags sane-backends 2>/dev/null)

BUILD := build

all: $(BUILD)/neat-scan $(BUILD)/nd1000-probe $(BUILD)/libsane-neat.so.1 $(BUILD)/libsane-nd1000.so.1

$(BUILD):
	mkdir -p $@

$(BUILD)/nm1000.o: src/nm1000.c src/nm1000.h src/nm1000_tables.h | $(BUILD)
	$(CC) $(CFLAGS) $(USB_CFLAGS) -fvisibility=hidden -c -o $@ $<

$(BUILD)/neat-scan: src/neat-scan.c $(BUILD)/nm1000.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(USB_LIBS)

$(BUILD)/nd1000-probe: src/nd1000-probe.c | $(BUILD)
	$(CC) $(CFLAGS) $(USB_CFLAGS) $(LDFLAGS) -o $@ $< $(USB_LIBS)

$(BUILD)/sane-neat.o: src/sane-neat.c src/nm1000.h | $(BUILD)
	$(CC) $(CFLAGS) $(USB_CFLAGS) $(SANE_CFLAGS) -fvisibility=hidden -c -o $@ $<

$(BUILD)/libsane-neat.so.1: $(BUILD)/sane-neat.o $(BUILD)/nm1000.o
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -Wl,-soname,libsane-neat.so.1 -Wl,--no-undefined -o $@ $^ $(USB_LIBS)

$(BUILD)/libsane-nd1000.so.1: src/sane-nd1000.c | $(BUILD)
	$(CC) $(CFLAGS) $(USB_CFLAGS) $(SANE_CFLAGS) $(LDFLAGS) -fPIC -fvisibility=hidden -shared -Wl,-soname,libsane-nd1000.so.1 -o $@ $< $(USB_LIBS)

install: all
	install -Dm755 $(BUILD)/libsane-neat.so.1 $(DESTDIR)$(LIBDIR)/sane/libsane-neat.so.1
	ln -sf libsane-neat.so.1 $(DESTDIR)$(LIBDIR)/sane/libsane-neat.so
	install -Dm755 $(BUILD)/neat-scan $(DESTDIR)$(PREFIX)/bin/neat-scan
	install -Dm644 packaging/dll.d-neat $(DESTDIR)$(SYSCONFDIR)/sane.d/dll.d/neat
	install -Dm644 udev/70-neat-nm1000.rules $(DESTDIR)$(UDEVDIR)/70-neat-nm1000.rules

clean:
	rm -rf $(BUILD)

.PHONY: all install clean
