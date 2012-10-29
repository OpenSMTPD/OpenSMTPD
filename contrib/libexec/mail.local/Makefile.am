libexec_PROGRAMS =	mail.local

mail_local_SOURCES =	mail.local.c locking.c $(top_srcdir)/smtpd/log.c

EXTRA_DIST =		mail.local.h pathnames.h

INCLUDES = 		-I$(top_srcdir)/openbsd-compat

LIBCOMPAT =		$(top_builddir)/openbsd-compat/libopenbsd-compat.a

LDADD = 		$(LIBCOMPAT)

# need to define _GNU_SOURCE to get:
# EAI_NODATA defined
# {v,}asprintf
# setres{g,u}id
CFLAGS +=		-D_GNU_SOURCE
