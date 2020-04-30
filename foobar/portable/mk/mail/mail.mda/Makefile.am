include	$(top_srcdir)/mk/pathnames

pkglibexec_PROGRAMS =	mail.mda

mail_mda_SOURCES = $(smtpd_srcdir)/mail.mda.c
mail_mda_SOURCES+= $(smtpd_srcdir)/log.c

AM_CPPFLAGS=		-I$(top_srcdir)/smtpd			\
			-I$(top_srcdir)/openbsd-compat
if !NEED_ERR_H
AM_CPPFLAGS += -I$(top_srcdir)/openbsd-compat/err_h
endif

LIBCOMPAT =		$(top_builddir)/openbsd-compat/libopenbsd.a

LDADD = 		$(LIBCOMPAT)




uninstall-hook:
	rmdir	$(DESTDIR)$(pkglibexecdir) 2> /dev/null || /bin/true
