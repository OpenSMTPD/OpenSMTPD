# In OpenBSD, smtpd's files are installed this way:
#
# /etc/mail/smtpd.conf
# /usr/sbin/smtpd
#
#
# For OpenSMTPD portable, here's where files are installed:
# (assuming PREFIX=/usr/local)
#
# /usr/local/etc/smtpd.conf
# /usr/local/sbin/smtpd

include $(top_srcdir)/mk/pathnames

sbin_PROGRAMS=		smtpd

smtpd_SOURCES=		$(top_srcdir)/usr.sbin/smtpd/aliases.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/bounce.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/ca.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/compress_backend.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/config.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/control.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/dict.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/dispatcher.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/dns.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/esc.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/envelope.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/expand.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/forward.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/iobuf.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/limit.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/lka.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/lka_filter.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/lka_session.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/log.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/mda.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/mda_mbox.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/mda_unpriv.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/mda_variables.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/mproc.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/mailaddr.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/mta.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/mta_session.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/parse.y
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/proxy.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/queue.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/queue_backend.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/report_smtp.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/resolver.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/rfc5322.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/ruleset.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/runq.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/scheduler.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/scheduler_backend.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/smtp.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/smtp_session.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/smtpd.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/srs.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/ssl.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/stat_backend.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/table.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/to.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/tree.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/unpack_dns.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/util.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/waitq.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/ioev.c

# backends
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/crypto.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/compress_gzip.c
if HAVE_DB_API
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/table_db.c
endif
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/table_getpwnam.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/table_proc.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/table_static.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/queue_fs.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/queue_null.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/queue_proc.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/queue_ram.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/scheduler_null.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/scheduler_proc.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/scheduler_ramqueue.c
smtpd_SOURCES+=		$(top_srcdir)/usr.sbin/smtpd/stat_ramstat.c

# libasr
if NEED_LIBASR
smtpd_SOURCES+=		$(top_srcdir)/openbsd-compat/event_asr_run.c
smtpd_SOURCES+=		$(top_srcdir)/openbsd-compat/libasr/asr.c
smtpd_SOURCES+=		$(top_srcdir)/openbsd-compat/libasr/asr_compat.c
smtpd_SOURCES+=		$(top_srcdir)/openbsd-compat/libasr/asr_debug.c
smtpd_SOURCES+=		$(top_srcdir)/openbsd-compat/libasr/asr_utils.c
smtpd_SOURCES+=		$(top_srcdir)/openbsd-compat/libasr/getaddrinfo_async.c
smtpd_SOURCES+=		$(top_srcdir)/openbsd-compat/libasr/gethostnamadr_async.c
smtpd_SOURCES+=		$(top_srcdir)/openbsd-compat/libasr/getnameinfo_async.c
smtpd_SOURCES+=		$(top_srcdir)/openbsd-compat/libasr/getnetnamadr_async.c
smtpd_SOURCES+=		$(top_srcdir)/openbsd-compat/libasr/res_search_async.c
smtpd_SOURCES+=		$(top_srcdir)/openbsd-compat/libasr/res_send_async.c
endif

# libtls
smtpd_SOURCES+=		$(top_srcdir)/openbsd-compat/libtls/tls.c
smtpd_SOURCES+=		$(top_srcdir)/openbsd-compat/libtls/tls_client.c
smtpd_SOURCES+=		$(top_srcdir)/openbsd-compat/libtls/tls_bio_cb.c
smtpd_SOURCES+=		$(top_srcdir)/openbsd-compat/libtls/tls_config.c
smtpd_SOURCES+=		$(top_srcdir)/openbsd-compat/libtls/tls_conninfo.c
smtpd_SOURCES+=		$(top_srcdir)/openbsd-compat/libtls/tls_keypair.c
smtpd_SOURCES+=		$(top_srcdir)/openbsd-compat/libtls/tls_server.c
smtpd_SOURCES+=		$(top_srcdir)/openbsd-compat/libtls/tls_ocsp.c
smtpd_SOURCES+=		$(top_srcdir)/openbsd-compat/libtls/tls_peer.c
smtpd_SOURCES+=		$(top_srcdir)/openbsd-compat/libtls/tls_signer.c
smtpd_SOURCES+=		$(top_srcdir)/openbsd-compat/libtls/tls_util.c
smtpd_SOURCES+=		$(top_srcdir)/openbsd-compat/libtls/tls_verify.c
smtpd_SOURCES+=		$(top_srcdir)/openbsd-compat/libtls/by_mem.c
smtpd_SOURCES+=		$(top_srcdir)/openbsd-compat/libtls/openssl.c

AM_CPPFLAGS=		-DIO_TLS \
			-I$(top_srcdir)/usr.sbin/smtpd \
			-I$(srcdir) $(PATHS) @DEFS@

LDADD=			$(LIBOBJS) $(DB_LIB)

MANPAGES=		aliases.5.out forward.5.out smtpd.8.out	\
			smtpd.conf.5.out smtpd-filters.7.out \
			smtpd-tables.7.out table.5.out

MANPAGES_IN=		$(top_srcdir)/usr.sbin/smtpd/aliases.5
MANPAGES_IN+=		$(top_srcdir)/usr.sbin/smtpd/forward.5
MANPAGES_IN+=		$(top_srcdir)/usr.sbin/smtpd/smtpd.8
MANPAGES_IN+=		$(top_srcdir)/usr.sbin/smtpd/smtpd.conf.5
MANPAGES_IN+=		$(top_srcdir)/usr.sbin/smtpd/smtpd-filters.7
MANPAGES_IN+=		$(top_srcdir)/usr.sbin/smtpd/smtpd-tables.7
MANPAGES_IN+=		$(top_srcdir)/usr.sbin/smtpd/table.5

CONFIGFILES=		smtpd.conf.out
CONFIGFILES_IN=		$(top_srcdir)/usr.sbin/smtpd/smtpd.conf

EXTRA_DIST=		$(CONFIGFILES_IN) $(MANPAGES_IN)


EXTRA_DIST+=		$(top_srcdir)/usr.sbin/smtpd/rfc5322.h
EXTRA_DIST+=		$(top_srcdir)/usr.sbin/smtpd/unpack_dns.h
EXTRA_DIST+=		$(top_srcdir)/usr.sbin/smtpd/tree.h
EXTRA_DIST+=		$(top_srcdir)/usr.sbin/smtpd/smtp.h
EXTRA_DIST+=		$(top_srcdir)/usr.sbin/smtpd/smtpd.h
EXTRA_DIST+=		$(top_srcdir)/usr.sbin/smtpd/smtpd-api.h
EXTRA_DIST+=		$(top_srcdir)/usr.sbin/smtpd/smtpd-defines.h
EXTRA_DIST+=		$(top_srcdir)/usr.sbin/smtpd/ioev.h
EXTRA_DIST+=		$(top_srcdir)/usr.sbin/smtpd/iobuf.h
EXTRA_DIST+=		$(top_srcdir)/usr.sbin/smtpd/log.h
EXTRA_DIST+=		$(top_srcdir)/usr.sbin/smtpd/ssl.h
EXTRA_DIST+=		$(top_srcdir)/usr.sbin/smtpd/parser.h
EXTRA_DIST+=		$(top_srcdir)/usr.sbin/smtpd/dict.h

PATHSUBS=		-e 's|/etc/mail/|$(sysconfdir)/|g'			\
			-e 's|/var/run/smtpd.sock|$(sockdir)/smtpd.sock|g' \
			-e 's|/usr/local/libexec/smtpd/|$(pkglibexecdir)|g'

FIXPATHSCMD=		$(SED) $(PATHSUBS)

$(MANPAGES): $(MANPAGES_IN)
	manpage=$(top_srcdir)/usr.sbin/smtpd/`echo $@ | sed 's/\.out$$//'`; \
	if test "$(MANTYPE)" = "man"; then \
		$(FIXPATHSCMD) $${manpage} | $(AWK) -f $(srcdir)/../mdoc2man.awk > $@; \
	else \
		$(FIXPATHSCMD) $${manpage} > $@; \
	fi

$(CONFIGFILES): $(CONFIGFILES_IN)
	conffile=$(top_srcdir)/usr.sbin/smtpd/`echo $@ | sed 's/.out$$//'`; \
	$(CAT) $${conffile} > $@


# smtpd.conf
# newaliases makemap
install-exec-hook: $(CONFIGFILES) $(MANPAGES)
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)
	$(MKDIR_P) $(DESTDIR)$(bindir)
	$(MKDIR_P) $(DESTDIR)$(mandir)/$(mansubdir)5
	$(MKDIR_P) $(DESTDIR)$(mandir)/$(mansubdir)7
	$(MKDIR_P) $(DESTDIR)$(mandir)/$(mansubdir)8

	@if [ ! -f $(DESTDIR)$(sysconfdir)/smtpd.conf ]; then			\
		$(INSTALL) -m 644 smtpd.conf.out $(DESTDIR)$(sysconfdir)/smtpd.conf; \
	else									\
		echo "$(DESTDIR)$(sysconfdir)/smtpd.conf already exists, install will not overwrite"; \
	fi

	$(INSTALL) -m 644 aliases.5.out		$(DESTDIR)$(mandir)/$(mansubdir)5/aliases.5
	$(INSTALL) -m 644 forward.5.out		$(DESTDIR)$(mandir)/$(mansubdir)5/forward.5
	$(INSTALL) -m 644 table.5.out		$(DESTDIR)$(mandir)/$(mansubdir)5/table.5
	$(INSTALL) -m 644 smtpd.8.out		$(DESTDIR)$(mandir)/$(mansubdir)8/smtpd.8
	$(INSTALL) -m 644 smtpd.conf.5.out	$(DESTDIR)$(mandir)/$(mansubdir)5/smtpd.conf.5
	$(INSTALL) -m 644 smtpd-filters.7.out	$(DESTDIR)$(mandir)/$(mansubdir)7/smtpd-filters.7
	$(INSTALL) -m 644 smtpd-tables.7.out	$(DESTDIR)$(mandir)/$(mansubdir)7/smtpd-tables.7
	rm	aliases.5.out forward.5.out table.5.out \
		smtpd.8.out smtpd.conf.5.out smtpd-filters.7.out smtpd-tables.7.out smtpd.conf.out

uninstall-hook:
# XXX to make "make distcheck" happy we need to rm smtpd.conf
	rm -f	$(DESTDIR)$(sysconfdir)/smtpd.conf				\
		$(DESTDIR)$(mandir)/$(mansubdir)5/aliases.5			\
		$(DESTDIR)$(mandir)/$(mansubdir)5/forward.5			\
		$(DESTDIR)$(mandir)/$(mansubdir)5/table.5			\
		$(DESTDIR)$(mandir)/$(mansubdir)5/smtpd.conf.5			\
		$(DESTDIR)$(mandir)/$(mansubdir)8/smtpd.8			\
		$(DESTDIR)$(mandir)/$(mansubdir)7/smtpd-filters.7		\
		$(DESTDIR)$(mandir)/$(mansubdir)7/smtpd-tables.7
	rmdir	$(DESTDIR)$(mandir)/$(mansubdir)5 \
		$(DESTDIR)$(mandir)/$(mansubdir)7 \
		$(DESTDIR)$(mandir)/$(mansubdir)8 2> /dev/null || true
