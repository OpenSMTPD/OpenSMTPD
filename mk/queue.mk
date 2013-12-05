AM_CPPFLAGS	 = -I$(smtpd_srcdir)
AM_CPPFLAGS	+= -I$(compat_srcdir)

LIBCOMPAT	 = $(top_builddir)/openbsd-compat/libopenbsd-compat.a
LDADD		 = $(LIBCOMPAT)

SRCS 	 = $(smtpd_srcdir)/log.c
SRCS	+= $(backends_srcdir)/queue_utils.c
SRCS	+= $(smtpd_srcdir)/queue_api.c
SRCS	+= $(smtpd_srcdir)/tree.c
SRCS	+= $(smtpd_srcdir)/dict.c
