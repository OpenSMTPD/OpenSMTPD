#	$OpenBSD: Makefile,v 1.1 2013/07/20 09:06:46 eric Exp $

.PATH: ${.CURDIR}/..

PROG=	table-mysql

SRCS=	table_mysql.c
SRCS+=	table_api.c
SRCS+=	dict.c
SRCS+=	log.c

NOMAN=	noman

BINDIR=	/usr/libexec/smtpd

DPADD=	${LIBUTIL}
LDADD=	-lutil -L/usr/local/lib -lmysqlclient

CFLAGS+=	-I/usr/local/include
CFLAGS+=	-g3 -ggdb -I${.CURDIR}/..
CFLAGS+=	-Wall -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=	-Wmissing-declarations
CFLAGS+=	-Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+=	-Wsign-compare -Wbounded
CFLAGS+=	-DNO_IO
#CFLAGS+=	-Werror # during development phase (breaks some archs) 

.include <bsd.prog.mk>
