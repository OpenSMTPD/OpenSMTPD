include	$(top_srcdir)/mk/pathnames

if HAVE_MAILWRAPPER
USE_MAILWRAPPER=1
pkglibexec_PROGRAMS=	makemap
else
USE_MAILWRAPPER=0
sbin_PROGRAMS=	makemap
endif

makemap_SOURCES=	$(smtpd_srcdir)/parse.y
makemap_SOURCES+=	$(smtpd_srcdir)/makemap.c
makemap_SOURCES+=	$(smtpd_srcdir)/aliases.c
makemap_SOURCES+=	$(smtpd_srcdir)/expand.c
makemap_SOURCES+=	$(smtpd_srcdir)/limit.c
makemap_SOURCES+=	$(smtpd_srcdir)/log.c
makemap_SOURCES+=	$(smtpd_srcdir)/util.c
makemap_SOURCES+=	$(smtpd_srcdir)/table.c
makemap_SOURCES+=	$(smtpd_srcdir)/dict.c
makemap_SOURCES+=	$(smtpd_srcdir)/tree.c
makemap_SOURCES+=	$(smtpd_srcdir)/to.c
makemap_SOURCES+=	$(smtpd_srcdir)/table_static.c
makemap_SOURCES+=	$(smtpd_srcdir)/table_db.c
makemap_SOURCES+=	$(smtpd_srcdir)/table_getpwnam.c
makemap_SOURCES+=	$(smtpd_srcdir)/table_proc.c

makemap_CFLAGS=		-DNO_IO


AM_CPPFLAGS=		-I$(smtpd_srcdir)	\
			-I$(compat_srcdir)	\
			-I$(asr_srcdir)

LIBCOMPAT=		$(top_builddir)/openbsd-compat/libopenbsd-compat.a

LDADD=			$(LIBCOMPAT)

# need to define _GNU_SOURCE to get:
# EAI_NODATA defined
# {v,}asprintf
# setres{g,u}id
CFLAGS+=		-D_GNU_SOURCE
CPPFLAGS=		-I$(srcdir) @CPPFLAGS@ $(PATHS) @DEFS@

MANPAGES=		makemap.8.out newaliases.8.out
MANPAGES_IN=		$(smtpd_srcdir)/makemap.8
MANPAGES_IN+=		$(smtpd_srcdir)/newaliases.8

EXTRA_DIST=		$(MANPAGES_IN)

PATHSUBS=		-e 's|/usr/libexec|$(libexecdir)|g'			\
			-e 's|/etc/mail/|$(sysconfdir)/|g'

FIXPATHSCMD=		$(SED) $(PATHSUBS)

$(MANPAGES): $(MANPAGES_IN)
	manpage=$(smtpd_srcdir)/`echo $@ | sed 's/\.out$$//'`; \
	if test "$(MANTYPE)" = "man"; then \
		$(FIXPATHSCMD) $${manpage} | $(AWK) -f $(srcdir)/../mdoc2man.awk > $@; \
	else \
		$(FIXPATHSCMD) $${manpage} > $@; \
	fi

# newaliases makemap
install-exec-hook: $(MANPAGES)
	$(MKDIR_P) $(DESTDIR)$(mandir)/$(mansubdir)8
	if test "$(USE_MAILWRAPPER)" = "0"; then \
		ln -s $(sbindir)/makemap $(DESTDIR)$(sbindir)/newaliases;\
	fi

	$(INSTALL) -m 644 makemap.8.out		$(DESTDIR)$(mandir)/$(mansubdir)8/makemap.8
	$(INSTALL) -m 644 newaliases.8.out	$(DESTDIR)$(mandir)/$(mansubdir)8/newaliases.8
	rm makemap.8.out newaliases.8.out

uninstall-hook:
	rm -f	$(DESTDIR)$(sbindir)/newaliases$(EXEEXT) \
		$(DESTDIR)$(sbindir)/makemap$(EXEEXT)
	rm -f	$(DESTDIR)$(mandir)/$(mansubdir)8/makemap.8			\
		$(DESTDIR)$(mandir)/$(mansubdir)8/newaliases.8
	rmdir	$(DESTDIR)$(pkglibexecdir) \
		$(DESTDIR)$(mandir)/$(mansubdir)8 2> /dev/null || /bin/true
