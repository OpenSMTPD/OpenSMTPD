include	$(top_srcdir)/mk/pathnames

sbin_PROGRAMS=		smtpctl

smtpctl_SOURCES=	$(top_srcdir)/usr.sbin/smtpd/enqueue.c
smtpctl_SOURCES+=	$(top_srcdir)/usr.sbin/smtpd/parser.c
smtpctl_SOURCES+=	$(top_srcdir)/usr.sbin/smtpd/log.c
smtpctl_SOURCES+=	$(top_srcdir)/usr.sbin/smtpd/envelope.c
smtpctl_SOURCES+=	$(top_srcdir)/usr.sbin/smtpd/queue_backend.c
smtpctl_SOURCES+=	$(top_srcdir)/usr.sbin/smtpd/queue_fs.c
smtpctl_SOURCES+=	$(top_srcdir)/usr.sbin/smtpd/smtpctl.c
smtpctl_SOURCES+=	$(top_srcdir)/usr.sbin/smtpd/spfwalk.c
smtpctl_SOURCES+=	$(top_srcdir)/usr.sbin/smtpd/util.c
smtpctl_SOURCES+=	$(top_srcdir)/usr.sbin/smtpd/unpack_dns.c
smtpctl_SOURCES+=	$(top_srcdir)/usr.sbin/smtpd/compress_backend.c
smtpctl_SOURCES+=	$(top_srcdir)/usr.sbin/smtpd/compress_gzip.c
smtpctl_SOURCES+=	$(top_srcdir)/usr.sbin/smtpd/to.c
smtpctl_SOURCES+=	$(top_srcdir)/usr.sbin/smtpd/expand.c
smtpctl_SOURCES+=	$(top_srcdir)/usr.sbin/smtpd/tree.c
smtpctl_SOURCES+=	$(top_srcdir)/usr.sbin/smtpd/dict.c

if HAVE_DB_API
smtpctl_SOURCES+=	$(top_srcdir)/usr.sbin/smtpd/config.c
smtpctl_SOURCES+=	$(top_srcdir)/usr.sbin/smtpd/parse.y
smtpctl_SOURCES+=	$(top_srcdir)/usr.sbin/smtpd/limit.c
smtpctl_SOURCES+=	$(top_srcdir)/usr.sbin/smtpd/table.c
smtpctl_SOURCES+=	$(top_srcdir)/usr.sbin/smtpd/table_static.c
smtpctl_SOURCES+=	$(top_srcdir)/usr.sbin/smtpd/table_db.c
smtpctl_SOURCES+=	$(top_srcdir)/usr.sbin/smtpd/table_getpwnam.c
smtpctl_SOURCES+=	$(top_srcdir)/usr.sbin/smtpd/table_proc.c
smtpctl_SOURCES+=	$(top_srcdir)/usr.sbin/smtpd/mailaddr.c
smtpctl_SOURCES+=	$(top_srcdir)/usr.sbin/smtpd/makemap.c
endif

smtpctl_SOURCES+=	$(top_srcdir)/usr.sbin/smtpd/crypto.c

# libasr
if NEED_LIBASR
smtpctl_SOURCES+=	$(top_srcdir)/openbsd-compat/event_asr_run.c
smtpctl_SOURCES+=	$(top_srcdir)/openbsd-compat/libasr/asr.c
smtpctl_SOURCES+=	$(top_srcdir)/openbsd-compat/libasr/asr_compat.c
smtpctl_SOURCES+=	$(top_srcdir)/openbsd-compat/libasr/asr_debug.c
smtpctl_SOURCES+=	$(top_srcdir)/openbsd-compat/libasr/asr_utils.c
smtpctl_SOURCES+=	$(top_srcdir)/openbsd-compat/libasr/getaddrinfo_async.c
smtpctl_SOURCES+=	$(top_srcdir)/openbsd-compat/libasr/gethostnamadr_async.c
smtpctl_SOURCES+=	$(top_srcdir)/openbsd-compat/libasr/getnameinfo_async.c
smtpctl_SOURCES+=	$(top_srcdir)/openbsd-compat/libasr/getnetnamadr_async.c
smtpctl_SOURCES+=	$(top_srcdir)/openbsd-compat/libasr/res_search_async.c
smtpctl_SOURCES+=	$(top_srcdir)/openbsd-compat/libasr/res_send_async.c
endif

smtpctl_CPPFLAGS=	-DNO_IO -DCONFIG_MINIMUM \
			-DPATH_GZCAT=\"$(ZCAT)\" \
			-DPATH_ENCRYPT=\"$(pkglibexecdir)/encrypt\" \
			-I$(top_srcdir)/usr.sbin/smtpd \
			-I$(srcdir) @CPPFLAGS@ $(PATHS) @DEFS@

LDADD=			$(LIBOBJS)
if HAVE_DB_API
LDADD+= $(DB_LIB)
endif

MANPAGES=		smtpctl.8.out sendmail.8.out makemap.8.out newaliases.8.out
MANPAGES_IN=		$(top_srcdir)/usr.sbin/smtpd/smtpctl.8 $(top_srcdir)/usr.sbin/smtpd/sendmail.8 $(top_srcdir)/usr.sbin/smtpd/makemap.8 $(top_srcdir)/usr.sbin/smtpd/newaliases.8

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
	rmdir	$(DESTDIR)$(mandir)/$(mansubdir)8 2> /dev/null || true
