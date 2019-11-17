pkglibexec_PROGRAMS =	mail.local

mail_local_SOURCES = mail.local.c
mail_local_SOURCES += locking.c
mail_local_SOURCES += $(top_srcdir)/smtpd/log.c

EXTRA_DIST =		mail.local.h pathnames.h

AM_CPPFLAGS = 		-I$(top_srcdir)/openbsd-compat

LIBCOMPAT =		$(top_builddir)/openbsd-compat/libopenbsd.a

LDADD = 		$(LIBCOMPAT)

# need to define _GNU_SOURCE to get:
# EAI_NODATA defined
# {v,}asprintf
# setres{g,u}id
#CFLAGS +=		-D_GNU_SOURCE

uninstall-hook:
	rmdir	$(DESTDIR)$(pkglibexecdir) 2> /dev/null || /bin/true
