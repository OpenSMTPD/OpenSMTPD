pkglibexec_PROGRAMS =	lockspool

lockspool_SOURCES = lockspool.c
lockspool_SOURCES += locking.c
lockspool_SOURCES += $(top_srcdir)/smtpd/log.c

EXTRA_DIST =		mail.local.h pathnames.h

AM_CPPFLAGS = 		-I$(top_srcdir)/openbsd-compat -I$(top_srcdir)/mail.local

LIBCOMPAT =		$(top_builddir)/openbsd-compat/libopenbsd-compat.a

LDADD = 		$(LIBCOMPAT)

install-exec-hook: $(CONFIGFILES) $(MANPAGES)
	chown root $(DESTDIR)$(pkglibexecdir)/lockspool || true
	chmod 4555 $(DESTDIR)$(pkglibexecdir)/lockspool || true

uninstall-hook:
	rmdir $(DESTDIR)$(pkglibexecdir) 2> /dev/null || /bin/true
