#	$OpenBSD$

.PATH:		${.CURDIR}/..

PROG=	makemap
BINOWN=	root

BINMODE?=555

BINDIR=	/usr/libexec/smtpd
MAN=	makemap.8 newaliases.8
# do not override default manpages for now
NOMAN=	noman

CFLAGS+=	-g3 -ggdb -I${.CURDIR}/..
CFLAGS+=	-Wall -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=	-Wmissing-declarations
CFLAGS+=	-Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+=	-Wsign-compare -Wbounded
CFLAGS+=	-DNO_IO

SRCS=		aliases.c
SRCS+=		dict.c
SRCS+=		expand.c
SRCS+=		limit.c
SRCS+=		log.c
SRCS+=		makemap.c
SRCS+=		parse.y
SRCS+=		table.c
SRCS+=		to.c
SRCS+=		tree.c
SRCS+=		util.c

SRCS+=		table_static.c
SRCS+=		table_db.c
SRCS+=		table_getpwnam.c
SRCS+=		table_proc.c

DPADD+= ${LIBUTIL} ${LIBCRYPTO} ${LIBZ}
LDADD+= -lutil -lcrypto -lz
.include <bsd.prog.mk>
