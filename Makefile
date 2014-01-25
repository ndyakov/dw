CFLAGS		= -g -O3 -Wall -Wextra
LINKFLAGS	= -lpthread

DESTDIR		=
PREFIX		= /usr/local
SBINDIR		= $(PREFIX)/sbin

OSD		= aircrack-ng/src/osdep
LIBS		= -L$(OSD) -losdep
LIBOSD		= $(OSD)/libosdep.so


all: osd dw

osd:
	$(MAKE) -C $(OSD)

$(LIBOSD):
	$(MAKE) -C $(OSD)

dw: dw.c $(OSD)/libosdep.a
	$(CC) $(CFLAGS) $(LINKFLAGS) $^ -o $@ $(LIBS)

install: dw
	$(MAKE) -C $(OSD) install
	install -D -m 0755 $^ $(DESTDIR)/$(SBINDIR)/$^

clean:
	rm -f dw
	$(MAKE) -C $(OSD) clean

distclean: clean
