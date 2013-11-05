AM_CPPFLAGS	 = -I$(smtpd_srcdir)
AM_CPPFLAGS	+= -I$(compat_srcdir)

LIBCOMPAT	= $(top_builddir)/openbsd-compat/libopenbsd-compat.a
LDADD		= $(LIBCOMPAT)

SRCS	 = $(smtpd_srcdir)/log.c
SRCS	+= $(smtpd_srcdir)/table_api.c
SRCS	+= $(smtpd_srcdir)/tree.c
SRCS	+= $(smtpd_srcdir)/dict.c
