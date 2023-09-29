include	$(top_srcdir)/mk/pathnames

pkglibexec_PROGRAMS =	mail.mda

mail_mda_SOURCES = $(top_srcdir)/usr.sbin/smtpd/mail.mda.c
mail_mda_SOURCES+= $(top_srcdir)/usr.sbin/smtpd/log.c

dist_man8_MANS =	$(top_srcdir)/usr.sbin/smtpd/mail.mda.8

AM_CPPFLAGS=		-I$(top_srcdir)/usr.sbin/smtpd	\
			-I$(top_srcdir)/openbsd-compat

LIBCOMPAT =		$(top_builddir)/openbsd-compat/libopenbsd.a

LDADD = 		$(LIBCOMPAT)




uninstall-hook:
	rmdir	$(DESTDIR)$(pkglibexecdir) 2> /dev/null || true
