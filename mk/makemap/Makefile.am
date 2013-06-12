# In OpenBSD, smtpd's files are installed this way:
#
# /usr/bin/newaliases --> /usr/sbin/mailwrapper --> /usr/libexec/smtpd/makemap
# /usr/sbin/makemap   --> /usr/sbin/mailwrapper --> /usr/libexec/smtpd/makemap
#
#
# For OpenSMTPD portable, here's where files are installed:
# (assuming PREFIX=/usr/local)
#
# /usr/local/bin/newaliases --> /usr/local/libexec/opensmtpd-portable/makemap
# /usr/local/sbin/makemap   --> /usr/local/libexec/opensmtpd-portable/makemap
#

include	$(top_srcdir)/mk/pathnames

pkglibexec_PROGRAMS=	makemap

makemap_SOURCES=	$(smtpd_srcdir)/parse.y
makemap_SOURCES+=	$(smtpd_srcdir)/makemap.c
makemap_SOURCES+=	$(smtpd_srcdir)/aliases.c
makemap_SOURCES+=	$(smtpd_srcdir)/expand.c
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

INCLUDES=		-I$(smtpd_srcdir)	\
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

EXTRA_DIST=		iobuf.h ioev.h log.h parser.h smtpd.h smtpd-api.h	\
			smtpd-defines.h	ssl.h					\
			$(CONFIGFILES_IN) $(MANPAGES_IN)

PATHSUBS=		-e 's|/usr/libexec|$(libexecdir)|g'
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

# newaliases makemap
install-exec-hook: $(MANPAGES)
	$(MKDIR_P) $(DESTDIR)$(bindir)
	$(MKDIR_P) $(DESTDIR)$(mandir)/$(mansubdir)8

	ln -f $(DESTDIR)$(pkglibexecdir)/makemap$(EXEEXT)			\
		$(DESTDIR)$(bindir)/newaliases$(EXEEXT);

	ln -f $(DESTDIR)$(pkglibexecdir)/makemap$(EXEEXT)			\
		$(DESTDIR)$(sbindir)/makemap$(EXEEXT);

	$(INSTALL) -m 644 makemap.8.out		$(DESTDIR)$(mandir)/$(mansubdir)8/makemap.8
	$(INSTALL) -m 644 newaliases.8.out	$(DESTDIR)$(mandir)/$(mansubdir)8/newaliases.8
	rm makemap.8.out newaliases.8.out

uninstall-hook:
# XXX to make "make distcheck" happy we need to rm smtpd.conf
	rm -f	$(DESTDIR)$(bindir)/newaliases$(EXEEXT) \
		$(DESTDIR)$(sbindir)/makemap$(EXEEXT)
	rm -f	$(DESTDIR)$(mandir)/$(mansubdir)8/makemap.8			\
		$(DESTDIR)$(mandir)/$(mansubdir)8/newaliases.8
	rmdir	$(DESTDIR)$(pkglibexecdir) \
		$(DESTDIR)$(mandir)/$(mansubdir)8 2> /dev/null || /bin/true
