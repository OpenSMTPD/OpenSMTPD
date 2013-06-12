include	$(top_srcdir)/mk/pathnames

bin_PROGRAMS=		smtpscript

smtpscript_SOURCES=	$(regress_srcdir)/smtpscript.c
smtpscript_SOURCES+=	$(regress_srcdir)/iobuf.c
smtpscript_SOURCES+=	$(regress_srcdir)/parse.y
smtpscript_SOURCES+=	$(regress_srcdir)/ssl.c
smtpscript_SOURCES+=	$(smtpd_srcdir)/log.c

smtpscript_CFLAGS=	-DIO_SSL

# compat
INCLUDES=		-I$(regress_srcdir)	\
			-I$(compat_srcdir)

LIBCOMPAT=		$(top_builddir)/openbsd-compat/libopenbsd-compat.a

LDADD=			$(LIBCOMPAT)

# need to define _GNU_SOURCE to get:
# EAI_NODATA defined
# {v,}asprintf
# setres{g,u}id
CFLAGS+=		-D_GNU_SOURCE
CPPFLAGS=		-I$(srcdir) @CPPFLAGS@ @DEFS@

install-exec-hook:
	$(MKDIR_P) $(DESTDIR)$(bindir)

uninstall-hook:
	rm -f $(DESTDIR)$(bindir)/smtpscript$(EXEEXT)

EXTRA_DIST=		$(regress_srcdir)/iobuf.h $(regress_srcdir)/smtpscript.h
