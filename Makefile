CFLAGS		= -g -O3 -Wall -Wextra
LINKFLAGS	= -lpthread

DESTDIR		=
PREFIX		= /usr/local
SBINDIR		= $(PREFIX)/sbin
MANDIR          = $(PREFIX)/share/man/man8
MANFILE		= dw.8
OSD		= aircrack-ng/src/osdep
LIBS		= -L$(OSD) -losdep
LIBOSD		= $(OSD)/libosdep.so

COPY            = cp
MAKEDIR         = mkdir
CHMOD           = chmod
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
	$(MAKEDIR) -p -m 755 $(MANDIR)
	$(COPY) $(MANFILE) $(MANDIR)
	$(CHMOD) 755 $(MANDIR)/$(MANFILE)
clean:
	rm -f dw
	$(MAKE) -C $(OSD) clean

distclean: clean
