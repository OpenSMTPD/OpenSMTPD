include	$(top_srcdir)/mk/pathnames

sbin_PROGRAMS=		smtpctl

if HAVE_MAILWRAPPER
USE_MAILWRAPPER=1
else
USE_MAILWRAPPER=0
endif

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
smtpctl_SOURCES+=	$(smtpd_srcdir)/dict.c

if HAVE_GCM_CRYPTO
smtpctl_SOURCES+=	$(smtpd_srcdir)/crypto.c
endif

smtpctl_CFLAGS=		-DNO_IO
smtpctl_CFLAGS+=	-DPATH_GZCAT=\"$(ZCAT)\" \
			-DPATH_ENCRYPT=\"$(pkglibexecdir)/encrypt\"

AM_CPPFLAGS=		-I$(top_srcdir)/smtpd			\
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

MANPAGES=		smtpctl.8.out sendmail.8.out
MANPAGES_IN=		$(smtpd_srcdir)/smtpctl.8 $(smtpd_srcdir)/sendmail.8

EXTRA_DIST=		$(MANPAGES_IN)

PATHSUBS=		-e 's|/var/run/smtpd.sock|$(sockdir)/smtpd.sock|g'
FIXPATHSCMD=		$(SED) $(PATHSUBS)


$(MANPAGES): $(MANPAGES_IN)
	manpage=$(smtpd_srcdir)/`echo $@ | sed 's/\.out$$//'`; \
	if test "$(MANTYPE)" = "man"; then \
		$(FIXPATHSCMD) $${manpage} | $(AWK) -f $(srcdir)/../mdoc2man.awk > $@; \
	else \
		$(FIXPATHSCMD) $${manpage} > $@; \
	fi

install-exec-hook: $(CONFIGFILES) $(MANPAGES)
	$(MKDIR_P) $(DESTDIR)$(mandir)/$(mansubdir)8
	if test "$(USE_MAILWRAPPER)" = "0"; then \
		ln -s $(sbindir)/smtpctl  $(DESTDIR)$(sbindir)/mailq;\
		ln -s $(sbindir)/smtpctl  $(DESTDIR)$(bindir)/sendmail;\
	fi
	$(INSTALL) -m 644 smtpctl.8.out		$(DESTDIR)$(mandir)/$(mansubdir)8/smtpctl.8
	$(INSTALL) -m 644 sendmail.8.out	$(DESTDIR)$(mandir)/$(mansubdir)8/sendmail.8
	rm	smtpctl.8.out sendmail.8.out

uninstall-hook:
	rm -f	$(DESTDIR)$(mandir)/$(mansubdir)8/smtpctl.8			\
	rm -f	$(DESTDIR)$(mandir)/$(mansubdir)8/sendmail.8			\
	rmdir	$(DESTDIR)$(mandir)/$(mansubdir)8 2> /dev/null || /bin/true
	if test "$(USE_MAILWRAPPER)" = "0"; then \
		rm -f $(DESTDIR)$(sbindir)/mailq;\
		rm -f $(DESTDIR)$(bindir)/sendmail;\
	fi
