pkglibexec_PROGRAMS = encrypt

encrypt_SOURCES	= encrypt.c
encrypt_SOURCES	+= $(top_srcdir)/smtpd/log.c

AM_CPPFLAGS = -I$(top_srcdir)/openbsd-compat

LIBCOMPAT = $(top_builddir)/openbsd-compat/libopenbsd.a

LDADD =  $(LIBCOMPAT)

uninstall-hook:
	rmdir	$(DESTDIR)$(pkglibexecdir) 2> /dev/null || /bin/true
