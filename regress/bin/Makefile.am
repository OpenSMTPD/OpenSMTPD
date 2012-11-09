bin_PROGRAMS=		smtpscript

smtpscript_SOURCES=	smtpscript.c iobuf.c parse.y

# compat
smtpscript_SOURCES+=	$(top_srcdir)/smtpd/log.c

INCLUDES=		-I$(top_srcdir)/openbsd-compat

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
