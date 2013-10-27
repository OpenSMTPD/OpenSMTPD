pkglibexec_PROGRAMS =	encrypt	

encrypt_SOURCES =	encrypt.c $(top_srcdir)/smtpd/log.c

INCLUDES = 		-I$(top_srcdir)/openbsd-compat

LIBCOMPAT =		$(top_builddir)/openbsd-compat/libopenbsd-compat.a

LDADD = 		$(LIBCOMPAT)

uninstall-hook:
	rmdir	$(DESTDIR)$(pkglibexecdir) 2> /dev/null || /bin/true
