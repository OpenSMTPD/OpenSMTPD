#	$OpenBSD: Makefile,v 1.1 2018/04/26 13:57:13 eric Exp $

.PATH:	${.CURDIR}/..

PROG=	smtp

BINDIR=	/usr/bin
MAN=	smtp.1

#SRCS+=	iobuf.c
#SRCS+=	ioev.c
SRCS+=	iobuf2.c
SRCS+=	ioev2.c
SRCS+=	log.c
SRCS+=	smtp_client.c
SRCS+=	smtpc.c
#SRCS+=	ssl.c
#SRCS+=	ssl_smtpd.c

CPPFLAGS+= -DIO_TLS

LDADD+=	-levent -lutil -ltls -lcrypto -lm -lz
DPADD+=	${LIBEVENT} ${LIBUTIL} ${LIBTLS} ${LIBCRYPTO} ${LIBM} ${LIBZ}

.include <bsd.prog.mk>
