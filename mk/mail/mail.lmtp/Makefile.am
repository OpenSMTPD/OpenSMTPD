include	$(top_srcdir)/mk/pathnames

pkglibexec_PROGRAMS =	mail.lmtp

mail_lmtp_SOURCES = $(smtpd_srcdir)/mail.lmtp.c

AM_CPPFLAGS=		-I$(top_srcdir)/smtpd			\
			-I$(top_srcdir)/openbsd-compat

LIBCOMPAT =		$(top_builddir)/openbsd-compat/libopenbsd-compat.a

LDADD = 		$(LIBCOMPAT)




uninstall-hook:
	rmdir	$(DESTDIR)$(pkglibexecdir) 2> /dev/null || /bin/true
