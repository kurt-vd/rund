PROGS	= initd initc
default	: $(PROGS)

LOCALVERSION:= $(shell git describe --always --tags --dirty)
PREFIX	= /usr/local
CFLAGS	= -g0 -Os -Wall
CPPFLAGS = -D_GNU_SOURCE

-include config.mk

CPPFLAGS+= -DVERSION=\"$(LOCALVERSION)\"

.PHONY: clean install

initd: LDLIBS+= -lrt
initd: lib/libt.o

clean:
	rm -rf $(PROGS) $(wildcard *.o lib/*.o)

install: $(PROGS)
	@[ -d $(DESTDIR)$(PREFIX)/sbin ] || install -v -d $(DESTDIR)$(PREFIX)/sbin
	@install -v initd $(DESTDIR)$(PREFIX)/sbin
	@[ -d $(DESTDIR)$(PREFIX)/bin ] || install -v -d $(DESTDIR)$(PREFIX)/bin
	@install -v initc $(DESTDIR)$(PREFIX)/bin

