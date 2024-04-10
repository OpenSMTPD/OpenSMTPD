pkglibexec_PROGRAMS = encrypt

encrypt_SOURCES	= encrypt.c
encrypt_SOURCES	+= $(top_srcdir)/usr.sbin/smtpd/log.c

LDADD =  $(LIBOBJS) @BASIC_LIBS@

uninstall-hook:
	rmdir	$(DESTDIR)$(pkglibexecdir) 2> /dev/null || true
