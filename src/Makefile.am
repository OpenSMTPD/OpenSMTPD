# In OpenBSD, smptd's files are installed this way:
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
# /usr/local/etc/mail/smtpd.conf
# /usr/local/bin/mailq      --> /usr/sbin/smtpctl
# /usr/local/bin/newaliases --> /usr/local/libexec/opensmtpd-portable/makemap
# /usr/local/libexec/mail.local
# /usr/local/sbin/makemap   --> /usr/local/libexec/opensmtpd-portable/makemap
# /usr/local/sbin/smtpctl
# /usr/local/sbin/smtpd


if !HAVE_MAIL_LOCAL
SUBDIRS =		libexec
endif

sbin_PROGRAMS =		smtpd smtpctl
pkglibexec_PROGRAMS =	makemap

makemap_SOURCES =	parse.y makemap.c aliases.c expand.c log.c util.c map.c	\
			map_db.c map_stdio.c

smtpd_SOURCES =		aliases.c auth.c auth_bsd.c auth_pwd.c bounce.c		\
			iobuf.c ioev.c						\
			delivery.c delivery_filename.c delivery_maildir.c	\
			delivery_mbox.c delivery_mda.c				\
			config.c control.c dns.c expand.c envelope.c forward.c	\
			lka.c lka_session.c log.c map.c map_db.c map_stdio.c	\
			mda.c mfa.c mfa_session.c mta.c mta_session.c parse.y	\
			queue.c ruleset.c runner.c smtp.c			\
			smtp_session.c smtpd.c ssl.c ssl_privsep.c util.c asr.c \
			print.c pack.c dname.c res_random.c sockaddr.c 		\
			queue_backend.c queue_fsqueue.c				\
			user.c user_pwd.c stats.c scheduler.c scheduler_ramqueue.c

smtpd_CFLAGS =		-DIO_SSL

smtpctl_SOURCES =	enqueue.c parser.c log.c envelope.c			\
			queue_backend.c queue_fsqueue.c				\
			smtpctl.c stats.c util.c

EXTRA_DIST = 		asr.h client.h dnsdefs.h dnsutil.h filter.h log.h	\
			parser.h smtpd.h

INCLUDES = 		-I$(top_srcdir)/openbsd-compat

LIBCOMPAT =		$(top_builddir)/openbsd-compat/libopenbsd-compat.a

LDADD = 		$(LIBCOMPAT)

# need to define _GNU_SOURCE to get:
# EAI_NODATA defined
# {v,}asprintf
# setres{g,u}id
CFLAGS +=		-D_GNU_SOURCE
CPPFLAGS =		-I$(srcdir) @CPPFLAGS@ $(PATHS) @DEFS@

PATHS =			-DSMTPD_CONFDIR=\"$(sysconfdir)/mail\" \
			-DPATH_SMTPCTL=\"$(sbindir)/smtpctl\" \
			-DPATH_MAILLOCAL=\"$(libexecdir)/mail.local\"

MANPAGES =		makemap.8.out newaliases.8.out smtpctl.8.out smtpd.8.out smtpd.conf.5.out
MANPAGES_IN =		makemap.8 newaliases.8 smtpctl.8 smtpd.8 smtpd.conf.5

CONFIGFILES =		smtpd.conf.out
CONFIGFILES_IN =	smtpd.conf

PATHSUBS =		-e 's|/etc/mail/|$(sysconfdir)/mail/|g'			\
			-e 's|/usr/libexec|$(libexecdir)|g'			\
			-e 's|/var/run/smtpd.sock|$(sockdir)/smtpd.sock|g'

FIXPATHSCMD =		$(SED) $(PATHSUBS)

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
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)/mail
	$(MKDIR_P) $(DESTDIR)$(bindir)
	$(MKDIR_P) $(DESTDIR)$(mandir)/$(mansubdir)5
	$(MKDIR_P) $(DESTDIR)$(mandir)/$(mansubdir)8

	@if [ ! -f $(DESTDIR)$(sysconfdir)/mail/smtpd.conf ]; then		\
		$(INSTALL) -m 644 smtpd.conf.out $(DESTDIR)$(sysconfdir)/mail/smtpd.conf; \
	else									\
		echo "$(DESTDIR)$(sysconfdir)/mail/smtpd.conf already exists, install will not overwrite"; \
	fi

	@if [ ! -f $(DESTDIR)$(bindir)/mailq$(EXEEXT) ]; then			\
		ln $(DESTDIR)$(sbindir)/smtpctl$(EXEEXT)			\
			$(DESTDIR)$(bindir)/mailq$(EXEEXT);			\
	else 									\
		echo "$(DESTDIR)$(bindir)/mailq$(EXEEXT) already exists, install will not overwrite"; \
	fi

	@if [ ! -f $(DESTDIR)$(bindir)/newaliases$(EXEEXT) ]; then		\
		ln $(DESTDIR)$(pkglibexecdir)/makemap$(EXEEXT)			\
			$(DESTDIR)$(bindir)/newaliases$(EXEEXT);		\
	else 									\
		echo "$(DESTDIR)$(bindir)/newaliases$(EXEEXT) already exists, install will not overwrite"; \
	fi

	@if [ ! -f $(DESTDIR)$(sbindir)/makemap$(EXEEXT) ]; then		\
		ln $(DESTDIR)$(pkglibexecdir)/makemap$(EXEEXT)			\
			$(DESTDIR)$(sbindir)/makemap$(EXEEXT);			\
	else 									\
		echo "$(DESTDIR)$(sbindir)/makemap$(EXEEXT) already exists, install will not overwrite"; \
	fi

	$(INSTALL) -m 644 makemap.8.out		$(DESTDIR)$(mandir)/$(mansubdir)8/makemap.8
	$(INSTALL) -m 644 newaliases.8.out	$(DESTDIR)$(mandir)/$(mansubdir)8/newaliases.8
	$(INSTALL) -m 644 smtpctl.8.out		$(DESTDIR)$(mandir)/$(mansubdir)8/smtpctl.8
	$(INSTALL) -m 644 smtpd.8.out		$(DESTDIR)$(mandir)/$(mansubdir)8/smtpd.8
	$(INSTALL) -m 644 smtpd.conf.5.out	$(DESTDIR)$(mandir)/$(mansubdir)5/smtpd.conf.5


uninstall-hook:
	rm 	$(DESTDIR)$(bindir)/newaliases$(EXEEXT) \
		$(DESTDIR)$(sbindir)/makemap$(EXEEXT)
