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
CPPFLAGS=		-I$(srcdir) @CPPFLAGS@ @DEFS@

install-exec-hook:
	$(MKDIR_P) $(DESTDIR)$(bindir)

uninstall-hook:
	rm $(DESTDIR)$(bindir)/smtpscript(EXEEXT)
