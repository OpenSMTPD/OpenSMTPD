AM_CPPFLAGS	 = -I$(smtpd_srcdir)
AM_CPPFLAGS	+= -I$(compat_srcdir)
AM_CPPFLAGS	+= -I$(asr_srcdir)

SRCS	=  $(smtpd_srcdir)/filter_api.c
SRCS	+= $(smtpd_srcdir)/mproc.c
SRCS	+= $(smtpd_srcdir)/log.c
SRCS	+= $(smtpd_srcdir)/tree.c
SRCS	+= $(smtpd_srcdir)/util.c
SRCS	+= $(smtpd_srcdir)/iobuf.c
SRCS	+= $(smtpd_srcdir)/ioev.c

LIBCOMPAT	= $(top_builddir)/openbsd-compat/libopenbsd-compat.a
LDADD		= $(LIBCOMPAT)

CFLAGS=			-DNO_IO -DBUILD_FILTER

