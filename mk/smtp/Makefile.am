include	$(top_srcdir)/mk/pathnames

bin_PROGRAMS=		smtp

smtp_SOURCES=	$(top_srcdir)/usr.sbin/smtpd/iobuf.c
smtp_SOURCES+=	$(top_srcdir)/usr.sbin/smtpd/ioev.c
smtp_SOURCES+=	$(top_srcdir)/usr.sbin/smtpd/log.c
smtp_SOURCES+=	$(top_srcdir)/usr.sbin/smtpd/smtp_client.c
smtp_SOURCES+=	$(top_srcdir)/usr.sbin/smtpd/smtpc.c
smtp_SOURCES+=	$(top_srcdir)/usr.sbin/smtpd/ssl.c

# libtls
smtp_SOURCES+=	$(top_srcdir)/openbsd-compat/libtls/a_time_posix.c
smtp_SOURCES+=	$(top_srcdir)/openbsd-compat/libtls/tls.c
smtp_SOURCES+=	$(top_srcdir)/openbsd-compat/libtls/tls_client.c
smtp_SOURCES+=	$(top_srcdir)/openbsd-compat/libtls/tls_bio_cb.c
smtp_SOURCES+=	$(top_srcdir)/openbsd-compat/libtls/tls_config.c
smtp_SOURCES+=	$(top_srcdir)/openbsd-compat/libtls/tls_conninfo.c
smtp_SOURCES+=	$(top_srcdir)/openbsd-compat/libtls/tls_keypair.c
smtp_SOURCES+=	$(top_srcdir)/openbsd-compat/libtls/tls_server.c
smtp_SOURCES+=	$(top_srcdir)/openbsd-compat/libtls/tls_ocsp.c
smtp_SOURCES+=	$(top_srcdir)/openbsd-compat/libtls/tls_peer.c
smtp_SOURCES+=	$(top_srcdir)/openbsd-compat/libtls/tls_signer.c
smtp_SOURCES+=	$(top_srcdir)/openbsd-compat/libtls/tls_util.c
smtp_SOURCES+=	$(top_srcdir)/openbsd-compat/libtls/tls_verify.c
smtp_SOURCES+=	$(top_srcdir)/openbsd-compat/libtls/by_mem.c
smtp_SOURCES+=	$(top_srcdir)/openbsd-compat/libtls/openssl.c

AM_CPPFLAGS=		-DIO_TLS \
			-I$(top_srcdir)/usr.sbin/smtpd \
			-I$(top_srcdir)/openbsd-compat \
			-I$(top_srcdir)/openbsd-compat/libtls \
			-I$(srcdir) @CPPFLAGS@ $(PATHS) @DEFS@

LDADD=			$(LIBOBJS)

MANPAGES=		smtp.1.out
MANPAGES_IN=		$(top_srcdir)/usr.sbin/smtpd/smtp.1

EXTRA_DIST=		$(MANPAGES_IN)

PATHSUBS=		-e 's|/var/run/smtpd.sock|$(sockdir)/smtpd.sock|g'	\
			-e 's|/usr/libexec|$(libexecdir)|g'			\
			-e 's|/etc/mail/|$(sysconfdir)/|g'

FIXPATHSCMD=		$(SED) $(PATHSUBS)


$(MANPAGES): $(MANPAGES_IN)
	manpage=$(top_srcdir)/usr.sbin/smtpd/`echo $@ | sed 's/\.out$$//'`; \
	if test "$(MANTYPE)" = "man"; then \
		$(FIXPATHSCMD) $${manpage} | $(AWK) -f $(srcdir)/../mdoc2man.awk > $@; \
	else \
		$(FIXPATHSCMD) $${manpage} > $@; \
	fi

install-exec-hook: $(CONFIGFILES) $(MANPAGES)
	$(MKDIR_P) $(DESTDIR)$(mandir)/$(mansubdir)1
	$(INSTALL) -m 644 smtp.1.out		$(DESTDIR)$(mandir)/$(mansubdir)1/smtp.1
	rm smtp.1.out

uninstall-hook:
	rm -f	$(DESTDIR)$(mandir)/$(mansubdir)1/smtp.1
	rmdir	$(DESTDIR)$(mandir)/$(mansubdir)1 2> /dev/null || true
