include	$(top_srcdir)/mk/pathnames

sbin_PROGRAMS=		smtpctl

smtpctl_SOURCES=	$(smtpd_srcdir)/enqueue.c
smtpctl_SOURCES+=	$(smtpd_srcdir)/parser.c
smtpctl_SOURCES+=	$(smtpd_srcdir)/log.c
smtpctl_SOURCES+=	$(smtpd_srcdir)/envelope.c
smtpctl_SOURCES+=	$(smtpd_srcdir)/queue_backend.c
smtpctl_SOURCES+=	$(smtpd_srcdir)/queue_fs.c
smtpctl_SOURCES+=	$(smtpd_srcdir)/smtpctl.c
smtpctl_SOURCES+=	$(smtpd_srcdir)/spfwalk.c
smtpctl_SOURCES+=	$(smtpd_srcdir)/util.c
smtpctl_SOURCES+=	$(smtpd_srcdir)/unpack_dns.c
smtpctl_SOURCES+=	$(smtpd_srcdir)/compress_backend.c
smtpctl_SOURCES+=	$(smtpd_srcdir)/compress_gzip.c
smtpctl_SOURCES+=	$(smtpd_srcdir)/to.c
smtpctl_SOURCES+=	$(smtpd_srcdir)/expand.c
smtpctl_SOURCES+=	$(smtpd_srcdir)/tree.c
smtpctl_SOURCES+=	$(smtpd_srcdir)/dict.c

if HAVE_DB_API
smtpctl_SOURCES+=	$(smtpd_srcdir)/config.c
smtpctl_SOURCES+=	$(smtpd_srcdir)/parse.y
smtpctl_SOURCES+=	$(smtpd_srcdir)/limit.c
smtpctl_SOURCES+=	$(smtpd_srcdir)/table.c
smtpctl_SOURCES+=	$(smtpd_srcdir)/table_static.c
smtpctl_SOURCES+=	$(smtpd_srcdir)/table_db.c
smtpctl_SOURCES+=	$(smtpd_srcdir)/table_getpwnam.c
smtpctl_SOURCES+=	$(smtpd_srcdir)/table_proc.c
smtpctl_SOURCES+=	$(smtpd_srcdir)/mailaddr.c
smtpctl_SOURCES+=	$(smtpd_srcdir)/makemap.c
endif

smtpctl_SOURCES+=	$(smtpd_srcdir)/crypto.c

smtpctl_CFLAGS=		-DNO_IO -DCONFIG_MINIMUM
smtpctl_CFLAGS+=	-DPATH_GZCAT=\"$(ZCAT)\" \
			-DPATH_ENCRYPT=\"$(pkglibexecdir)/encrypt\"

AM_CPPFLAGS=		-I$(top_srcdir)/smtpd			\
			-I$(top_srcdir)/openbsd-compat
if !NEED_ERR_H
AM_CPPFLAGS += -I$(top_srcdir)/openbsd-compat/err_h
endif

LIBCOMPAT=		$(top_builddir)/openbsd-compat/libopenbsd.a

LDADD=			$(LIBCOMPAT)
if HAVE_DB_API
LDADD+= $(DB_LIB)
endif

# need to define _GNU_SOURCE to get:
# EAI_NODATA defined
# {v,}asprintf
# setres{g,u}id
CFLAGS+=		-D_GNU_SOURCE
CPPFLAGS=		-I$(srcdir) @CPPFLAGS@ $(PATHS) @DEFS@

MANPAGES=		smtpctl.8.out sendmail.8.out makemap.8.out newaliases.8.out
MANPAGES_IN=		$(smtpd_srcdir)/smtpctl.8 $(smtpd_srcdir)/sendmail.8 $(smtpd_srcdir)/makemap.8 $(smtpd_srcdir)/newaliases.8

EXTRA_DIST=		$(MANPAGES_IN)

PATHSUBS=		-e 's|/var/run/smtpd.sock|$(sockdir)/smtpd.sock|g'	\
			-e 's|/usr/libexec|$(libexecdir)|g'			\
			-e 's|/etc/mail/|$(sysconfdir)/|g'

FIXPATHSCMD=		$(SED) $(PATHSUBS)

if NEED_LIBASR
AM_CPPFLAGS+=	-I$(top_srcdir)/openbsd-compat/libasr
endif

$(MANPAGES): $(MANPAGES_IN)
	manpage=$(smtpd_srcdir)/`echo $@ | sed 's/\.out$$//'`; \
	if test "$(MANTYPE)" = "man"; then \
		$(FIXPATHSCMD) $${manpage} | $(AWK) -f $(srcdir)/../mdoc2man.awk > $@; \
	else \
		$(FIXPATHSCMD) $${manpage} > $@; \
	fi

install-exec-hook: $(CONFIGFILES) $(MANPAGES)
	$(MKDIR_P) $(DESTDIR)$(mandir)/$(mansubdir)8
	chgrp $(SMTPD_QUEUE_USER) $(DESTDIR)$(sbindir)/smtpctl || true
	chmod 2555 $(DESTDIR)$(sbindir)/smtpctl || true
	$(INSTALL) -m 644 smtpctl.8.out		$(DESTDIR)$(mandir)/$(mansubdir)8/smtpctl.8
	$(INSTALL) -m 644 sendmail.8.out	$(DESTDIR)$(mandir)/$(mansubdir)8/sendmail.8
	$(INSTALL) -m 644 makemap.8.out		$(DESTDIR)$(mandir)/$(mansubdir)8/makemap.8
	$(INSTALL) -m 644 newaliases.8.out	$(DESTDIR)$(mandir)/$(mansubdir)8/newaliases.8
	rm smtpctl.8.out sendmail.8.out makemap.8.out newaliases.8.out

uninstall-hook:
	rm -f	$(DESTDIR)$(mandir)/$(mansubdir)8/smtpctl.8
	rm -f	$(DESTDIR)$(mandir)/$(mansubdir)8/sendmail.8
	rm -f	$(DESTDIR)$(mandir)/$(mansubdir)8/makemap.8
	rm -f	$(DESTDIR)$(mandir)/$(mansubdir)8/newaliases.8
	rmdir	$(DESTDIR)$(mandir)/$(mansubdir)8 2> /dev/null || /bin/true
