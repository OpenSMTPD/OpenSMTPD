#	$OpenBSD$

.PATH:		${.CURDIR}/..

PROG=	smtpctl
BINOWN=	root

BINMODE?=555

BINDIR=	/usr/sbin
MAN=	smtpctl.8

CFLAGS+=	-g3 -ggdb -I${.CURDIR}/..
CFLAGS+=	-Wall -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=	-Wmissing-declarations
CFLAGS+=	-Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+=	-Wsign-compare -Wbounded
CFLAGS+=	-DNO_IO

SRCS=		enqueue.c
SRCS+=		parser.c
SRCS+=		log.c
SRCS+=		envelope.c
SRCS+=		crypto.c
SRCS+=		queue_backend.c
SRCS+=		queue_fs.c
SRCS+=		smtpctl.c util.c
SRCS+=		compress_backend.c
SRCS+=		compress_gzip.c
SRCS+=		to.c
SRCS+=		expand.c
SRCS+=		tree.c
SRCS+=		dict.c

LDADD+=	-lutil -lz -lcrypto
DPADD+=	${LIBUTIL} ${LIBZ} ${LIBCRYPTO}
.include <bsd.prog.mk>
