#	$OpenBSD$

CFLAGS	+= -DNO_IO -DBUILD_FILTER
CPPFLAGS+= -I${.CURDIR}/../../

SRCS	+= filter_api.c mproc.c log.c tree.c util.c csprng.c

LDADD	+= -levent -lutil

BINDIR	= /usr/libexec/smtpd
