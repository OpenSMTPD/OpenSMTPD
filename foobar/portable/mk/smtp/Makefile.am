include	$(top_srcdir)/mk/pathnames

bin_PROGRAMS=		smtp

smtp_SOURCES=	$(smtpd_srcdir)/iobuf.c
smtp_SOURCES+=	$(smtpd_srcdir)/ioev.c
smtp_SOURCES+=	$(smtpd_srcdir)/log.c
smtp_SOURCES+=	$(smtpd_srcdir)/smtp_client.c
smtp_SOURCES+=	$(smtpd_srcdir)/smtpc.c
smtp_SOURCES+=	$(smtpd_srcdir)/ssl.c
smtp_SOURCES+=	$(smtpd_srcdir)/ssl_verify.c

smtp_CFLAGS=		-DIO_TLS

AM_CPPFLAGS=		-I$(top_srcdir)/smtpd			\
			-I$(top_srcdir)/openbsd-compat
if !NEED_ERR_H
AM_CPPFLAGS += -I$(top_srcdir)/openbsd-compat/err_h
endif

LIBCOMPAT=		$(top_builddir)/openbsd-compat/libopenbsd.a

LDADD=			$(LIBCOMPAT)

# need to define _GNU_SOURCE to get:
# EAI_NODATA defined
# {v,}asprintf
# setres{g,u}id
CFLAGS+=		-D_GNU_SOURCE
CPPFLAGS=		-I$(srcdir) @CPPFLAGS@ $(PATHS) @DEFS@

MANPAGES=		smtp.1.out
MANPAGES_IN=		$(smtpd_srcdir)/smtp.1

EXTRA_DIST=		$(MANPAGES_IN)

PATHSUBS=		-e 's|/var/run/smtpd.sock|$(sockdir)/smtpd.sock|g'	\
			-e 's|/usr/libexec|$(libexecdir)|g'			\
			-e 's|/etc/mail/|$(sysconfdir)/|g'

FIXPATHSCMD=		$(SED) $(PATHSUBS)


$(MANPAGES): $(MANPAGES_IN)
	manpage=$(smtpd_srcdir)/`echo $@ | sed 's/\.out$$//'`; \
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
	rmdir	$(DESTDIR)$(mandir)/$(mansubdir)1 2> /dev/null || /bin/true
