#	$OpenBSD: Makefile,v 1.3 2012/08/02 13:38:39 okan Exp $

.PATH:		${.CURDIR}/..

CFLAGS	  = -DNO_IO
LIB	  = smtpdfilter
SRCS	  = filter_api.c dict.c tree.c util.c ioev.c iobuf.c log.c
DEBUGLIBS = no
NOPROFILE = yes
NOPIC=	yes

install:
	@echo -n

.include <bsd.own.mk>
.include <bsd.lib.mk>
