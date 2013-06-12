include	$(top_srcdir)/mk/pathnames

sbin_PROGRAMS=		smtpctl

smtpctl_SOURCES=	$(smtpd_srcdir)/enqueue.c
smtpctl_SOURCES+=	$(smtpd_srcdir)/parser.c
smtpctl_SOURCES+=	$(smtpd_srcdir)/log.c
smtpctl_SOURCES+=	$(smtpd_srcdir)/envelope.c
smtpctl_SOURCES+=	$(smtpd_srcdir)/queue_backend.c
smtpctl_SOURCES+=	$(smtpd_srcdir)/queue_fs.c
smtpctl_SOURCES+=	$(smtpd_srcdir)/smtpctl.c
smtpctl_SOURCES+=	$(smtpd_srcdir)/util.c
smtpctl_SOURCES+=	$(smtpd_srcdir)/compress_backend.c
smtpctl_SOURCES+=	$(smtpd_srcdir)/compress_gzip.c
smtpctl_SOURCES+=	$(smtpd_srcdir)/to.c
smtpctl_SOURCES+=	$(smtpd_srcdir)/expand.c
smtpctl_SOURCES+=	$(smtpd_srcdir)/tree.c

if HAVE_GCM_CRYPTO
smtpctl_SOURCES+=	$(smtpd_srcdir)/crypto.c
endif

smtpctl_CFLAGS=		-DNO_IO
smtpctl_CFLAGS+=	-DPATH_GZCAT=\"$(ZCAT)\"

INCLUDES=		-I$(top_srcdir)/smtpd			\
			-I$(top_srcdir)/openbsd-compat		\
			-I$(top_srcdir)/contrib/lib/libc/asr

LIBCOMPAT=		$(top_builddir)/openbsd-compat/libopenbsd-compat.a

LDADD=			$(LIBCOMPAT)

# need to define _GNU_SOURCE to get:
# EAI_NODATA defined
# {v,}asprintf
# setres{g,u}id
CFLAGS+=		-D_GNU_SOURCE
CPPFLAGS=		-I$(srcdir) @CPPFLAGS@ $(PATHS) @DEFS@

MANPAGES=		smtpctl.8.out
MANPAGES_IN=		$(smtpd_srcdir)/smtpctl.8

EXTRA_DIST=		iobuf.h ioev.h log.h parser.h smtpd.h smtpd-api.h	\
			smtpd-defines.h	ssl.h					\
			$(MANPAGES_IN)

PATHSUBS=		-e 's|/var/run/smtpd.sock|$(sockdir)/smtpd.sock|g'
FIXPATHSCMD=		$(SED) $(PATHSUBS)

$(MANPAGES): $(MANPAGES_IN)
	if test "$(MANTYPE)" = "cat"; then \
		manpage=$(smtpd_srcdir)/`echo $@ | sed 's/\.[1-9]\.out$$/\.0/'`; \
	else \
		manpage=$(smtpd_srcdir)/`echo $@ | sed 's/\.out$$//'`; \
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
	$(MKDIR_P) $(DESTDIR)$(bindir)
	$(MKDIR_P) $(DESTDIR)$(mandir)/$(mansubdir)8

	ln -f $(DESTDIR)$(sbindir)/smtpctl$(EXEEXT)				\
		$(DESTDIR)$(bindir)/mailq$(EXEEXT);

	$(INSTALL) -m 644 smtpctl.8.out		$(DESTDIR)$(mandir)/$(mansubdir)8/smtpctl.8
	rm	smtpctl.8.out

uninstall-hook:
# XXX to make "make distcheck" happy we need to rm smtpd.conf
#	rm $(DESTDIR)$(sysconfdir)/smtpd.conf
	rm -f	$(DESTDIR)$(bindir)/mailq$(EXEEXT)
	rm -f	$(DESTDIR)$(mandir)/$(mansubdir)8/smtpctl.8			\
	rmdir	$(DESTDIR)$(mandir)/$(mansubdir)8 2> /dev/null || /bin/true
