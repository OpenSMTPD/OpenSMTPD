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

smtpd_SOURCES=		$(smtpd_srcdir)/aliases.c
smtpd_SOURCES+=		$(smtpd_srcdir)/bounce.c
smtpd_SOURCES+=		$(smtpd_srcdir)/ca.c
smtpd_SOURCES+=		$(smtpd_srcdir)/cert.c
smtpd_SOURCES+=		$(smtpd_srcdir)/compress_backend.c
smtpd_SOURCES+=		$(smtpd_srcdir)/config.c
smtpd_SOURCES+=		$(smtpd_srcdir)/control.c
smtpd_SOURCES+=		$(smtpd_srcdir)/dict.c
smtpd_SOURCES+=		$(smtpd_srcdir)/dns.c
smtpd_SOURCES+=		$(smtpd_srcdir)/esc.c
smtpd_SOURCES+=		$(smtpd_srcdir)/envelope.c
smtpd_SOURCES+=		$(smtpd_srcdir)/expand.c
smtpd_SOURCES+=		$(smtpd_srcdir)/forward.c
smtpd_SOURCES+=		$(smtpd_srcdir)/iobuf.c
smtpd_SOURCES+=		$(smtpd_srcdir)/ioev.c
smtpd_SOURCES+=		$(smtpd_srcdir)/limit.c
smtpd_SOURCES+=		$(smtpd_srcdir)/lka.c
smtpd_SOURCES+=		$(smtpd_srcdir)/lka_filter.c
smtpd_SOURCES+=		$(smtpd_srcdir)/lka_proc.c
smtpd_SOURCES+=		$(smtpd_srcdir)/lka_report.c
smtpd_SOURCES+=		$(smtpd_srcdir)/lka_session.c
smtpd_SOURCES+=		$(smtpd_srcdir)/log.c
smtpd_SOURCES+=		$(smtpd_srcdir)/mda.c
smtpd_SOURCES+=		$(smtpd_srcdir)/mda_unpriv.c
smtpd_SOURCES+=		$(smtpd_srcdir)/mda_variables.c
smtpd_SOURCES+=		$(smtpd_srcdir)/mproc.c
smtpd_SOURCES+=		$(smtpd_srcdir)/mailaddr.c
smtpd_SOURCES+=		$(smtpd_srcdir)/mta.c
smtpd_SOURCES+=		$(smtpd_srcdir)/mta_session.c
smtpd_SOURCES+=		$(smtpd_srcdir)/parse.y
smtpd_SOURCES+=		$(smtpd_srcdir)/pony.c
smtpd_SOURCES+=		$(smtpd_srcdir)/proxy.c
smtpd_SOURCES+=		$(smtpd_srcdir)/queue.c
smtpd_SOURCES+=		$(smtpd_srcdir)/queue_backend.c
smtpd_SOURCES+=		$(smtpd_srcdir)/report_smtp.c
smtpd_SOURCES+=		$(smtpd_srcdir)/resolver.c
smtpd_SOURCES+=		$(smtpd_srcdir)/rfc5322.c
smtpd_SOURCES+=		$(smtpd_srcdir)/ruleset.c
smtpd_SOURCES+=		$(smtpd_srcdir)/runq.c
smtpd_SOURCES+=		$(smtpd_srcdir)/scheduler.c
smtpd_SOURCES+=		$(smtpd_srcdir)/scheduler_backend.c
smtpd_SOURCES+=		$(smtpd_srcdir)/smtp.c
smtpd_SOURCES+=		$(smtpd_srcdir)/smtp_session.c
smtpd_SOURCES+=		$(smtpd_srcdir)/smtpd.c
smtpd_SOURCES+=		$(smtpd_srcdir)/srs.c
smtpd_SOURCES+=		$(smtpd_srcdir)/ssl.c
smtpd_SOURCES+=		$(smtpd_srcdir)/ssl_smtpd.c
smtpd_SOURCES+=		$(smtpd_srcdir)/ssl_verify.c
smtpd_SOURCES+=		$(smtpd_srcdir)/stat_backend.c
smtpd_SOURCES+=		$(smtpd_srcdir)/table.c
smtpd_SOURCES+=		$(smtpd_srcdir)/to.c
smtpd_SOURCES+=		$(smtpd_srcdir)/tree.c
smtpd_SOURCES+=		$(smtpd_srcdir)/unpack_dns.c
smtpd_SOURCES+=		$(smtpd_srcdir)/util.c
smtpd_SOURCES+=		$(smtpd_srcdir)/waitq.c

# backends
smtpd_SOURCES+=		$(smtpd_srcdir)/crypto.c
smtpd_SOURCES+=		$(smtpd_srcdir)/compress_gzip.c
if HAVE_DB_API
smtpd_SOURCES+=		$(smtpd_srcdir)/table_db.c
endif
smtpd_SOURCES+=		$(smtpd_srcdir)/table_getpwnam.c
smtpd_SOURCES+=		$(smtpd_srcdir)/table_proc.c
smtpd_SOURCES+=		$(smtpd_srcdir)/table_static.c
smtpd_SOURCES+=		$(smtpd_srcdir)/queue_fs.c
smtpd_SOURCES+=		$(smtpd_srcdir)/queue_null.c
smtpd_SOURCES+=		$(smtpd_srcdir)/queue_proc.c
smtpd_SOURCES+=		$(smtpd_srcdir)/queue_ram.c
smtpd_SOURCES+=		$(smtpd_srcdir)/scheduler_null.c
smtpd_SOURCES+=		$(smtpd_srcdir)/scheduler_proc.c
smtpd_SOURCES+=		$(smtpd_srcdir)/scheduler_ramqueue.c
smtpd_SOURCES+=		$(smtpd_srcdir)/stat_ramstat.c


smtpd_CFLAGS=		-DIO_TLS
smtpd_CFLAGS+=		-DCA_FILE=\"$(CA_FILE)\"

AM_CPPFLAGS=		-I$(smtpd_srcdir)	\
			-I$(compat_srcdir)
if !SUPPORT_ERR_H
AM_CPPFLAGS += -I$(top_srcdir)/openbsd-compat/err_h
endif
if !SUPPORT_PATHS_H
AM_CPPFLAGS += -I$(top_srcdir)/openbsd-compat/paths_h
endif

LIBCOMPAT=		$(top_builddir)/openbsd-compat/libopenbsd-compat.a

LDADD=			$(LIBCOMPAT) $(DB_LIB) $(ASR_LIB)

# need to define _GNU_SOURCE to get:
# EAI_NODATA defined
# {v,}asprintf
# setres{g,u}id
CFLAGS+=		-D_GNU_SOURCE -DNEED_EVENT_ASR_RUN
CPPFLAGS=		-I$(srcdir) @CPPFLAGS@ $(PATHS) @DEFS@

MANPAGES=		aliases.5.out forward.5.out smtpd.8.out	\
			smtpd.conf.5.out table.5.out

MANPAGES_IN=		$(smtpd_srcdir)/aliases.5
MANPAGES_IN+=		$(smtpd_srcdir)/forward.5
MANPAGES_IN+=		$(smtpd_srcdir)/smtpd.8
MANPAGES_IN+=		$(smtpd_srcdir)/smtpd.conf.5
MANPAGES_IN+=		$(smtpd_srcdir)/table.5

CONFIGFILES=		smtpd.conf.out
CONFIGFILES_IN=		$(smtpd_srcdir)/smtpd.conf

EXTRA_DIST=		$(CONFIGFILES_IN) $(MANPAGES_IN)


EXTRA_DIST+=		$(smtpd_srcdir)/smtpd.h
EXTRA_DIST+=		$(smtpd_srcdir)/smtpd-api.h
EXTRA_DIST+=		$(smtpd_srcdir)/smtpd-defines.h
EXTRA_DIST+=		$(smtpd_srcdir)/ioev.h
EXTRA_DIST+=		$(smtpd_srcdir)/iobuf.h
EXTRA_DIST+=		$(smtpd_srcdir)/log.h
EXTRA_DIST+=		$(smtpd_srcdir)/ssl.h
EXTRA_DIST+=		$(smtpd_srcdir)/parser.h

EXTRA_DIST+=		$(backends_srcdir)/queue_utils.h
EXTRA_DIST+=		$(filters_srcdir)/asr_event.h

PATHSUBS=		-e 's|/etc/mail/|$(sysconfdir)/|g'			\
			-e 's|/var/run/smtpd.sock|$(sockdir)/smtpd.sock|g'

FIXPATHSCMD=		$(SED) $(PATHSUBS)

$(MANPAGES): $(MANPAGES_IN)
	manpage=$(smtpd_srcdir)/`echo $@ | sed 's/\.out$$//'`; \
	if test "$(MANTYPE)" = "man"; then \
		$(FIXPATHSCMD) $${manpage} | $(AWK) -f $(srcdir)/../mdoc2man.awk > $@; \
	else \
		$(FIXPATHSCMD) $${manpage} > $@; \
	fi

$(CONFIGFILES): $(CONFIGFILES_IN)
	conffile=$(smtpd_srcdir)/`echo $@ | sed 's/.out$$//'`; \
	$(CAT) $(srcdir)/$${conffile} > $@


# smtpd.conf
# newaliases makemap
install-exec-hook: $(CONFIGFILES) $(MANPAGES)
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)
	$(MKDIR_P) $(DESTDIR)$(bindir)
	$(MKDIR_P) $(DESTDIR)$(mandir)/$(mansubdir)5
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
	rm	aliases.5.out forward.5.out table.5.out \
		smtpd.8.out smtpd.conf.5.out smtpd.conf.out

uninstall-hook:
# XXX to make "make distcheck" happy we need to rm smtpd.conf
#	rm $(DESTDIR)$(sysconfdir)/smtpd.conf
	rm -f	$(DESTDIR)$(mandir)/$(mansubdir)5/aliases.5			\
		$(DESTDIR)$(mandir)/$(mansubdir)5/forward.5			\
		$(DESTDIR)$(mandir)/$(mansubdir)5/table.5			\
		$(DESTDIR)$(mandir)/$(mansubdir)5/smtpd.conf.5			\
		$(DESTDIR)$(mandir)/$(mansubdir)8/smtpd.8
	rmdir	$(DESTDIR)$(mandir)/$(mansubdir)5 \
		$(DESTDIR)$(mandir)/$(mansubdir)8 2> /dev/null || /bin/true
