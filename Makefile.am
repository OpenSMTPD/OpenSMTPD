SUBDIRS =		contrib openbsd-compat

# TODO:
# - CONFIGFILES_IN from smtpd/Makefile.am
# - FIXPATHSCMD in manpages

EXTRA_DIST =		CHANGES.md \
			LICENSE \
			etc/README.md \
			etc/aliases

ACLOCAL_AMFLAGS =	-I m4

AM_CPPFLAGS =		-DSMTPD_CONFDIR=\"$(sysconfdir)\" \
			-DPATH_CHROOT=\"$(PRIVSEP_PATH)\" \
			-DPATH_SMTPCTL=\"$(sbindir)/smtpctl\" \
			-DPATH_MAILLOCAL=\"$(pkglibexecdir)/mail.local\" \
			-DPATH_MAKEMAP=\"$(sbindir)/makemap\" \
			-DPATH_LIBEXEC=\"$(pkglibexecdir)\" \
			@DEFS@

LDADD = 		$(LIBOBJS)

dist_man1_MANS =	usr.sbin/smtpd/smtp.1

dist_man5_MANS =	usr.sbin/smtpd/aliases.5 \
			usr.sbin/smtpd/forward.5 \
			usr.sbin/smtpd/smtpd.conf.5 \
			usr.sbin/smtpd/table.5

dist_man7_MANS =	usr.sbin/smtpd/smtpd-filters.7

dist_man8_MANS =	usr.sbin/smtpd/mail.lmtp.8 \
			usr.sbin/smtpd/mail.maildir.8 \
			usr.sbin/smtpd/mail.mboxfile.8 \
			usr.sbin/smtpd/mail.mda.8 \
			usr.sbin/smtpd/makemap.8 \
			usr.sbin/smtpd/newaliases.8 \
			usr.sbin/smtpd/sendmail.8 \
			usr.sbin/smtpd/smtpctl.8 \
			usr.sbin/smtpd/smtpd.8

pkglibexec_PROGRAMS =	mail.lmtp mail.maildir mail.mboxfile mail.mda
bin_PROGRAMS =		smtp
sbin_PROGRAMS =		smtpd smtpctl

noinst_LIBRARIES =	libtls.a

libtls_a_SOURCES =	openbsd-compat/libtls/asn.c \
			openbsd-compat/libtls/tls.c \
			openbsd-compat/libtls/tls_client.c \
			openbsd-compat/libtls/tls_bio_cb.c \
			openbsd-compat/libtls/tls_config.c \
			openbsd-compat/libtls/tls_conninfo.c \
			openbsd-compat/libtls/tls_keypair.c \
			openbsd-compat/libtls/tls_server.c \
			openbsd-compat/libtls/tls_ocsp.c \
			openbsd-compat/libtls/tls_peer.c \
			openbsd-compat/libtls/tls_util.c \
			openbsd-compat/libtls/tls_verify.c \
			openbsd-compat/libtls/by_mem.c \
			openbsd-compat/libtls/openssl.c

if NEED_LIBASR
noinst_LIBRARIES +=	libasr.a
LIBASR =		libasr.a
libasr_a_SOURCES =	openbsd-compat/event_asr_run.c \
			openbsd-compat/libasr/asr.c \
			openbsd-compat/libasr/asr_compat.c \
			openbsd-compat/libasr/asr_debug.c \
			openbsd-compat/libasr/asr_utils.c \
			openbsd-compat/libasr/getaddrinfo_async.c \
			openbsd-compat/libasr/gethostnamadr_async.c \
			openbsd-compat/libasr/getnameinfo_async.c \
			openbsd-compat/libasr/getnetnamadr_async.c \
			openbsd-compat/libasr/res_search_async.c \
			openbsd-compat/libasr/res_send_async.c
endif

mail_lmtp_SOURCES =	usr.sbin/smtpd/mail.lmtp.c \
			usr.sbin/smtpd/log.c
mail_lmtp_LDFLAGS =	@BASIC_LIBS@

mail_maildir_SOURCES =	usr.sbin/smtpd/mail.maildir.c \
			usr.sbin/smtpd/log.c
mail_maildir_LDFLAGS =	@BASIC_LIBS@

mail_mboxfile_SOURCES =	usr.sbin/smtpd/mail.mboxfile.c \
			usr.sbin/smtpd/log.c
mail_mboxfile_LDFLAGS =	@BASIC_LIBS@

mail_mda_SOURCES =	usr.sbin/smtpd/mail.mda.c \
			usr.sbin/smtpd/log.c
mail_mda_LDFLAGS =	@BASIC_LIBS@

smtp_CPPFLAGS =		-DIO_TLS $(AM_CPPFLAGS)
smtp_LDADD =		libtls.a $(LIBASR) $(LIBOBJS) @FULL_LIBS@
smtp_SOURCES =		usr.sbin/smtpd/iobuf.c \
			usr.sbin/smtpd/ioev.c \
			usr.sbin/smtpd/log.c \
			usr.sbin/smtpd/smtp_client.c \
			usr.sbin/smtpd/smtpc.c \
			usr.sbin/smtpd/ssl.c

smtpctl_CPPFLAGS =	-DNO_IO -DCONFIG_MINIMUM \
			-DPATH_GZCAT=\"$(ZCAT)\" \
			-DPATH_ENCRYPT=\"$(pkglibexecdir)/encrypt\" \
			$(AM_CPPFLAGS)

smtpctl_LDADD =		$(LIBASR) $(LIBOBJS) @FULL_LIBS@

smtpctl_SOURCES =	usr.sbin/smtpd/compress_backend.c \
			usr.sbin/smtpd/compress_gzip.c \
			usr.sbin/smtpd/crypto.c \
			usr.sbin/smtpd/dict.c \
			usr.sbin/smtpd/enqueue.c \
			usr.sbin/smtpd/envelope.c \
			usr.sbin/smtpd/expand.c \
			usr.sbin/smtpd/log.c \
			usr.sbin/smtpd/parser.c \
			usr.sbin/smtpd/queue_backend.c \
			usr.sbin/smtpd/queue_fs.c \
			usr.sbin/smtpd/smtpctl.c \
			usr.sbin/smtpd/spfwalk.c \
			usr.sbin/smtpd/to.c \
			usr.sbin/smtpd/tree.c \
			usr.sbin/smtpd/unpack_dns.c \
			usr.sbin/smtpd/util.c

if HAVE_DB_API
smtpctl_SOURCES +=	usr.sbin/smtpd/config.c \
			usr.sbin/smtpd/limit.c \
			usr.sbin/smtpd/mailaddr.c \
			usr.sbin/smtpd/makemap.c \
			usr.sbin/smtpd/parse.y \
			usr.sbin/smtpd/table.c \
			usr.sbin/smtpd/table_db.c \
			usr.sbin/smtpd/table_getpwnam.c \
			usr.sbin/smtpd/table_proc.c \
			usr.sbin/smtpd/table_static.c
endif

smtpd_CPPFLAGS =	-DIO_TLS $(AM_CPPFLAGS)
smtpd_LDADD =		libtls.a $(LIBASR) $(LIBOBJS) @FULL_LIBS@

smtpd_SOURCES =		usr.sbin/smtpd/aliases.c
smtpd_SOURCES +=	usr.sbin/smtpd/bounce.c
smtpd_SOURCES +=	usr.sbin/smtpd/ca.c
smtpd_SOURCES +=	usr.sbin/smtpd/compress_backend.c
smtpd_SOURCES +=	usr.sbin/smtpd/config.c
smtpd_SOURCES +=	usr.sbin/smtpd/control.c
smtpd_SOURCES +=	usr.sbin/smtpd/dict.c
smtpd_SOURCES +=	usr.sbin/smtpd/dispatcher.c
smtpd_SOURCES +=	usr.sbin/smtpd/dns.c
smtpd_SOURCES +=	usr.sbin/smtpd/envelope.c
smtpd_SOURCES +=	usr.sbin/smtpd/esc.c
smtpd_SOURCES +=	usr.sbin/smtpd/expand.c
smtpd_SOURCES +=	usr.sbin/smtpd/forward.c
smtpd_SOURCES +=	usr.sbin/smtpd/iobuf.c
smtpd_SOURCES +=	usr.sbin/smtpd/ioev.c
smtpd_SOURCES +=	usr.sbin/smtpd/limit.c
smtpd_SOURCES +=	usr.sbin/smtpd/lka.c
smtpd_SOURCES +=	usr.sbin/smtpd/lka_filter.c
smtpd_SOURCES +=	usr.sbin/smtpd/lka_session.c
smtpd_SOURCES +=	usr.sbin/smtpd/log.c
smtpd_SOURCES +=	usr.sbin/smtpd/mailaddr.c
smtpd_SOURCES +=	usr.sbin/smtpd/mda.c
smtpd_SOURCES +=	usr.sbin/smtpd/mda_mbox.c
smtpd_SOURCES +=	usr.sbin/smtpd/mda_unpriv.c
smtpd_SOURCES +=	usr.sbin/smtpd/mda_variables.c
smtpd_SOURCES +=	usr.sbin/smtpd/mproc.c
smtpd_SOURCES +=	usr.sbin/smtpd/mta.c
smtpd_SOURCES +=	usr.sbin/smtpd/mta_session.c
smtpd_SOURCES +=	usr.sbin/smtpd/parse.y
smtpd_SOURCES +=	usr.sbin/smtpd/proxy.c
smtpd_SOURCES +=	usr.sbin/smtpd/queue.c
smtpd_SOURCES +=	usr.sbin/smtpd/queue_backend.c
smtpd_SOURCES +=	usr.sbin/smtpd/report_smtp.c
smtpd_SOURCES +=	usr.sbin/smtpd/resolver.c
smtpd_SOURCES +=	usr.sbin/smtpd/rfc5322.c
smtpd_SOURCES +=	usr.sbin/smtpd/ruleset.c
smtpd_SOURCES +=	usr.sbin/smtpd/runq.c
smtpd_SOURCES +=	usr.sbin/smtpd/scheduler.c
smtpd_SOURCES +=	usr.sbin/smtpd/scheduler_backend.c
smtpd_SOURCES +=	usr.sbin/smtpd/smtp.c
smtpd_SOURCES +=	usr.sbin/smtpd/smtp_session.c
smtpd_SOURCES +=	usr.sbin/smtpd/smtpd.c
smtpd_SOURCES +=	usr.sbin/smtpd/srs.c
smtpd_SOURCES +=	usr.sbin/smtpd/ssl.c
smtpd_SOURCES +=	usr.sbin/smtpd/stat_backend.c
smtpd_SOURCES +=	usr.sbin/smtpd/table.c
smtpd_SOURCES +=	usr.sbin/smtpd/to.c
smtpd_SOURCES +=	usr.sbin/smtpd/tree.c
smtpd_SOURCES +=	usr.sbin/smtpd/unpack_dns.c
smtpd_SOURCES +=	usr.sbin/smtpd/util.c
smtpd_SOURCES +=	usr.sbin/smtpd/waitq.c

# backends
smtpd_SOURCES +=	usr.sbin/smtpd/compress_gzip.c
smtpd_SOURCES +=	usr.sbin/smtpd/crypto.c
smtpd_SOURCES +=	usr.sbin/smtpd/queue_fs.c
smtpd_SOURCES +=	usr.sbin/smtpd/queue_null.c
smtpd_SOURCES +=	usr.sbin/smtpd/queue_proc.c
smtpd_SOURCES +=	usr.sbin/smtpd/queue_ram.c
smtpd_SOURCES +=	usr.sbin/smtpd/scheduler_null.c
smtpd_SOURCES +=	usr.sbin/smtpd/scheduler_proc.c
smtpd_SOURCES +=	usr.sbin/smtpd/scheduler_ramqueue.c
smtpd_SOURCES +=	usr.sbin/smtpd/stat_ramstat.c
smtpd_SOURCES +=	usr.sbin/smtpd/table_getpwnam.c
smtpd_SOURCES +=	usr.sbin/smtpd/table_proc.c
smtpd_SOURCES +=	usr.sbin/smtpd/table_static.c
if HAVE_DB_API
smtpd_SOURCES +=	usr.sbin/smtpd/table_db.c
endif

install-exec-hook:
	chgrp $(SMTPD_QUEUE_USER) $(DESTDIR)$(sbindir)/smtpctl || true
	chmod 2555 $(DESTDIR)$(sbindir)/smtpctl || true

uninstall-hook:
	rmdir	$(DESTDIR)$(pkglibexecdir) 2> /dev/null || true
