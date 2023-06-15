include	$(top_srcdir)/mk/pathnames

pkglibexec_PROGRAMS =	mail.mboxfile

mail_mboxfile_SOURCES = $(top_srcdir)/usr.sbin/smtpd/mail.mboxfile.c
mail_mboxfile_SOURCES+= $(top_srcdir)/usr.sbin/smtpd/log.c

dist_man8_MANS =	$(top_srcdir)/usr.sbin/smtpd/mail.mboxfile.8

AM_CPPFLAGS=		-I$(top_srcdir)/usr.sbin/smtpd	\
			-I$(top_srcdir)/openbsd-compat
if !NEED_ERR_H
AM_CPPFLAGS += -I$(top_srcdir)/openbsd-compat/err_h
endif

LIBCOMPAT =		$(top_builddir)/openbsd-compat/libopenbsd.a

LDADD = 		$(LIBCOMPAT)




uninstall-hook:
	rmdir	$(DESTDIR)$(pkglibexecdir) 2> /dev/null || true
