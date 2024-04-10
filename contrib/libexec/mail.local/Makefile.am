pkglibexec_PROGRAMS =	mail.local

mail_local_SOURCES = mail.local.c
mail_local_SOURCES += locking.c
mail_local_SOURCES += $(top_srcdir)/usr.sbin/smtpd/log.c

dist_man8_MANS = mail.local.8

EXTRA_DIST =		mail.local.h pathnames.h

AM_CPPFLAGS = 		-DPATH_LIBEXEC=\"$(pkglibexecdir)\"

LDADD = 		$(LIBOBJS) @BASIC_LIBS@

uninstall-hook:
	rmdir	$(DESTDIR)$(pkglibexecdir) 2> /dev/null || true
