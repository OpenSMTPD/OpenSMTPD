#	$OpenBSD: Makefile,v 1.3 2012/08/02 13:38:39 okan Exp $

CFLAGS	+= -DNO_IO
CPPFLAGS+= -I../../
SRCS	+= filter_api.c dict.c tree.c util.c iobuf.c log.c to.c

LDADD	+= -levent -lutil
