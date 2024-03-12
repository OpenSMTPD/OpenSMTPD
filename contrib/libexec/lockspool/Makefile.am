pkglibexec_PROGRAMS =	lockspool

lockspool_SOURCES = lockspool.c
lockspool_SOURCES += locking.c
lockspool_SOURCES += $(top_srcdir)/usr.sbin/smtpd/log.c

dist_man1_MANS =	lockspool.1

EXTRA_DIST =		mail.local.h pathnames.h

AM_CPPFLAGS = 		-I$(top_srcdir)/mail.local

LDADD = 		$(LIBOBJS) @BASIC_LIBS@

install-exec-hook: $(CONFIGFILES) $(MANPAGES)
	chown root $(DESTDIR)$(pkglibexecdir)/lockspool || true
	chmod 4555 $(DESTDIR)$(pkglibexecdir)/lockspool || true

uninstall-hook:
	rmdir $(DESTDIR)$(pkglibexecdir) 2> /dev/null || true
