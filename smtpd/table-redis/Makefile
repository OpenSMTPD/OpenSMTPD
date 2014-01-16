#	$OpenBSD$

.PATH: ${.CURDIR}/..

PROG=	table-redis

SRCS=	table_redis.c
SRCS+=	table_api.c
SRCS+=	dict.c
SRCS+=	log.c

NOMAN=	noman

BINDIR=	/usr/libexec/smtpd

DPADD=	${LIBUTIL}
LDADD=	-lutil -L/usr/local/lib -lhiredis

CFLAGS+=	-I/usr/local/include/hiredis
CFLAGS+=	-g3 -ggdb -I${.CURDIR}/..
CFLAGS+=	-Wall -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=	-Wmissing-declarations
CFLAGS+=	-Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+=	-Wsign-compare -Wbounded
CFLAGS+=	-DNO_IO
#CFLAGS+=	-Werror # during development phase (breaks some archs) 

.include <bsd.prog.mk>
