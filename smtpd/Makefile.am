# In OpenBSD, smtpd's files are installed this way:
#
# /etc/mail/smtpd.conf
# /usr/bin/mailq      --> /usr/sbin/mailwrapper --> /usr/sbin/smtpctl
# /usr/bin/newaliases --> /usr/sbin/mailwrapper --> /usr/libexec/smtpd/makemap
# /usr/libexec/mail.local
# /usr/sbin/makemap   --> /usr/sbin/mailwrapper --> /usr/libexec/smtpd/makemap
# /usr/sbin/smtpctl
# /usr/sbin/smtpd
#
#
# For OpenSMTPD portable, here's where files are installed:
# (assuming PREFIX=/usr/local)
#
# /usr/local/etc/smtpd.conf
# /usr/local/bin/mailq      --> /usr/sbin/smtpctl
# /usr/local/bin/newaliases --> /usr/local/libexec/opensmtpd-portable/makemap
# /usr/local/libexec/mail.local
# /usr/local/sbin/makemap   --> /usr/local/libexec/opensmtpd-portable/makemap
# /usr/local/sbin/smtpctl
# /usr/local/sbin/smtpd

sbin_PROGRAMS=		smtpd smtpctl
pkglibexec_PROGRAMS=	makemap

makemap_SOURCES=	parse.y makemap.c aliases.c expand.c log.c util.c	\
			table.c	table_db.c table_getpwnam.c table_static.c	\
			tree.c dict.c

makemap_CFLAGS=		-DNO_IO

smtpd_SOURCES=		aliases.c auth.c bounce.c compress_backend.c config.c	\
			control.c delivery.c dict.c dns.c envelope.c expand.c	\
			forward.c iobuf.c ioev.c lka.c lka_session.c log.c	\
			mda.c mfa.c mfa_session.c mta.c mta_session.c parse.y	\
			queue.c queue_backend.c ruleset.c			\
			scheduler.c scheduler_backend.c	smtp.c smtp_session.c	\
			smtpd.c ssl.c ssl_privsep.c stat_backend.c table.c	\
			tree.c util.c
# backends
smtpd_SOURCES+=		auth_bsd.c
smtpd_SOURCES+=		auth_pwd.c
smtpd_SOURCES+=		compress_gzip.c
smtpd_SOURCES+=		delivery_filename.c
smtpd_SOURCES+=		delivery_maildir.c
smtpd_SOURCES+=		delivery_mbox.c
smtpd_SOURCES+=		delivery_mda.c
smtpd_SOURCES+=		queue_fsqueue.c
smtpd_SOURCES+=		queue_ram.c
smtpd_SOURCES+=		scheduler_ramqueue.c
smtpd_SOURCES+=		stat_ramstat.c
#smtpd_SOURCES+=	stat_sqlite.c
smtpd_SOURCES+=		table_db.c
smtpd_SOURCES+=		table_getpwnam.c
smtpd_SOURCES+=		table_static.c

# resolver
smtpd_SOURCES+=		../contrib/lib/libc/asr/asr.c				\
			../contrib/lib/libc/asr/asr_debug.c			\
			../contrib/lib/libc/asr/asr_utils.c			\
			../contrib/lib/libc/asr/gethostnamadr_async.c		\
			../contrib/lib/libc/asr/res_send_async.c		\
			../contrib/lib/libc/asr/getaddrinfo_async.c		\
			../contrib/lib/libc/asr/getnameinfo_async.c

smtpd_CFLAGS=		-DIO_SSL -DASR_OPT_THREADSAFE=0

smtpctl_SOURCES=	enqueue.c parser.c log.c envelope.c			\
			queue_backend.c queue_fsqueue.c				\
			smtpctl.c util.c					\
			compress_backend.c compress_gzip.c

smtpctl_CFLAGS=		-DNO_IO

INCLUDES=		-I$(top_srcdir)/openbsd-compat				\
			-I$(top_srcdir)/contrib/lib/libc/asr

LIBCOMPAT=		$(top_builddir)/openbsd-compat/libopenbsd-compat.a

LDADD=			$(LIBCOMPAT)

# need to define _GNU_SOURCE to get:
# EAI_NODATA defined
# {v,}asprintf
# setres{g,u}id
CFLAGS+=		-D_GNU_SOURCE
CPPFLAGS=		-I$(srcdir) @CPPFLAGS@ $(PATHS) @DEFS@

PATHS=			-DSMTPD_CONFDIR=\"$(sysconfdir)\" \
			-DPATH_SMTPCTL=\"$(sbindir)/smtpctl\" \
			-DPATH_MAILLOCAL=\"$(libexecdir)/mail.local\"

MANPAGES=		aliases.5.out forward.5.out makemap.8.out		\
			newaliases.8.out smtpctl.8.out smtpd.8.out		\
			smtpd.conf.5.out
MANPAGES_IN=		aliases.5     forward.5     makemap.8			\
			newaliases.8     smtpctl.8     smtpd.8			\
			smtpd.conf.5

CONFIGFILES=		smtpd.conf.out
CONFIGFILES_IN=		smtpd.conf

EXTRA_DIST=		filter_api.h iobuf.h ioev.h log.h parser.h smtpd.h	\
			../contrib/lib/libc/asr/asr.h				\
			../contrib/lib/libc/asr/asr_private.h			\
			$(CONFIGFILES_IN) $(MANPAGES_IN)

PATHSUBS=		-e 's|/etc/mail/|$(sysconfdir)/|g'			\
			-e 's|/usr/libexec|$(libexecdir)|g'			\
			-e 's|/var/run/smtpd.sock|$(sockdir)/smtpd.sock|g'

FIXPATHSCMD=		$(SED) $(PATHSUBS)

$(MANPAGES): $(MANPAGES_IN)
	if test "$(MANTYPE)" = "cat"; then \
		manpage=$(srcdir)/`echo $@ | sed 's/\.[1-9]\.out$$/\.0/'`; \
	else \
		manpage=$(srcdir)/`echo $@ | sed 's/\.out$$//'`; \
	fi; \
	if test "$(MANTYPE)" = "man"; then \
		$(FIXPATHSCMD) $${manpage} | $(AWK) -f $(srcdir)/mdoc2man.awk > $@; \
	else \
		$(FIXPATHSCMD) $${manpage} > $@; \
	fi

$(CONFIGFILES): $(CONFIGFILES_IN)
	conffile=`echo $@ | sed 's/.out$$//'`; \
	$(FIXPATHSCMD) $(srcdir)/$${conffile} > $@


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

	ln -f $(DESTDIR)$(sbindir)/smtpctl$(EXEEXT)				\
		$(DESTDIR)$(bindir)/mailq$(EXEEXT);

	ln -f $(DESTDIR)$(pkglibexecdir)/makemap$(EXEEXT)			\
		$(DESTDIR)$(bindir)/newaliases$(EXEEXT);

	ln -f $(DESTDIR)$(pkglibexecdir)/makemap$(EXEEXT)			\
		$(DESTDIR)$(sbindir)/makemap$(EXEEXT);

	$(INSTALL) -m 644 aliases.5.out		$(DESTDIR)$(mandir)/$(mansubdir)5/aliases.5
	$(INSTALL) -m 644 forward.5.out		$(DESTDIR)$(mandir)/$(mansubdir)5/forward.5
	$(INSTALL) -m 644 makemap.8.out		$(DESTDIR)$(mandir)/$(mansubdir)8/makemap.8
	$(INSTALL) -m 644 newaliases.8.out	$(DESTDIR)$(mandir)/$(mansubdir)8/newaliases.8
	$(INSTALL) -m 644 smtpctl.8.out		$(DESTDIR)$(mandir)/$(mansubdir)8/smtpctl.8
	$(INSTALL) -m 644 smtpd.8.out		$(DESTDIR)$(mandir)/$(mansubdir)8/smtpd.8
	$(INSTALL) -m 644 smtpd.conf.5.out	$(DESTDIR)$(mandir)/$(mansubdir)5/smtpd.conf.5


uninstall-hook:
	rm 	$(DESTDIR)$(bindir)/newaliases$(EXEEXT) \
		$(DESTDIR)$(sbindir)/makemap$(EXEEXT)
