#	$OpenBSD: Makefile,v 1.16 2012/10/14 11:58:23 gilles Exp $

.PATH:		${.CURDIR}/..

PROG=	makemap
BINOWN=	root

BINMODE?=555

BINDIR=	/usr/libexec/smtpd
MAN=	makemap.8 newaliases.8

CFLAGS+=	-g3 -ggdb -I${.CURDIR}/..
CFLAGS+=	-Wall -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=	-Wmissing-declarations
CFLAGS+=	-Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+=	-Wsign-compare -Wbounded
CFLAGS+=	-DNO_IO

SRCS=	parse.y makemap.c aliases.c expand.c log.c util.c table.c dict.c tree.c to.c

SRCS+=	table_static.c
SRCS+=	table_db.c
SRCS+=	table_getpwnam.c

DPADD+= ${LIBUTIL} ${LIBCRYPTO}
LDADD+= -lutil -lcrypto
.include <bsd.prog.mk>
