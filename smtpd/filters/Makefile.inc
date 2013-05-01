#	$OpenBSD: Makefile,v 1.3 2012/08/02 13:38:39 okan Exp $

CFLAGS	+= -DNO_IO -DBUILD_FILTER
CPPFLAGS+= -I../../

SRCS	+= filter_api.c mproc.c log.c tree.c util.c

#SRCS	+= filter_api.c dict.c tree.c util.c iobuf.c

LDADD	+= -levent -lutil

BINDIR	= /usr/libexec/smtpd
