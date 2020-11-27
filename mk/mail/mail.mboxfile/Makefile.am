include	$(top_srcdir)/mk/pathnames

pkglibexec_PROGRAMS =	mail.mboxfile

mail_mboxfile_SOURCES = $(top_srcdir)/usr.sbin/smtpd/mail.mboxfile.c
mail_mboxfile_SOURCES+= $(top_srcdir)/usr.sbin/smtpd/log.c

AM_CPPFLAGS=		-I$(top_srcdir)/smtpd			\
			-I$(top_srcdir)/openbsd-compat
if !NEED_ERR_H
AM_CPPFLAGS += -I$(top_srcdir)/openbsd-compat/err_h
endif

LIBCOMPAT =		$(top_builddir)/openbsd-compat/libopenbsd.a

LDADD = 		$(LIBCOMPAT)




uninstall-hook:
	rmdir	$(DESTDIR)$(pkglibexecdir) 2> /dev/null || /bin/true
