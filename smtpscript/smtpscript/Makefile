.PATH:	${.CURDIR}/..

PROG=	smtpscript
SRCS=	smtpscript.c iobuf.c parse.y ssl.c
NOMAN=	noman

LDADD+=         -lutil -lssl -lcrypto
DPADD+=         ${LIBEVENT} ${LIBUTIL} ${LIBSSL} ${LIBCRYPTO}
CPPFLAGS+=	-I${.CURDIR}/..
CPPFLAGS+=	-DIO_SSL

.include <bsd.prog.mk>
