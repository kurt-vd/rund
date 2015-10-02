PROGS	= rund runc sysreboot sockwait ktstamp
default	: $(PROGS)

LOCALVERSION:= $(shell git describe --always --tags --dirty)
PREFIX	= /usr/local
CFLAGS	= -g0 -Os -Wall
CPPFLAGS = -D_GNU_SOURCE

-include config.mk

CPPFLAGS+= -DVERSION=\"$(LOCALVERSION)\"

.PHONY: clean install

rund: LDLIBS+= -lrt
rund: lib/libt.o

runc: LDLIBS+= -lm

clean:
	rm -rf $(PROGS) $(wildcard *.o lib/*.o)

install: $(PROGS)
	@[ -d $(DESTDIR)$(PREFIX)/sbin ] || install -v -d $(DESTDIR)$(PREFIX)/sbin
	@install -v rund sysreboot $(DESTDIR)$(PREFIX)/sbin
	@[ -d $(DESTDIR)$(PREFIX)/bin ] || install -v -d $(DESTDIR)$(PREFIX)/bin
	@install -v $(filter-out rund sysreboot, $^) $(DESTDIR)$(PREFIX)/bin

