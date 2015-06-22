PROGS	= rund runc
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

clean:
	rm -rf $(PROGS) $(wildcard *.o lib/*.o)

install: $(PROGS)
	@[ -d $(DESTDIR)$(PREFIX)/bin ] || install -v -d $(DESTDIR)$(PREFIX)/bin
	@install -v $^ $(DESTDIR)$(PREFIX)/bin

