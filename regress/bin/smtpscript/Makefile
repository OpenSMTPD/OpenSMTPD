.PATH:	${.CURDIR}/..

PROG=	smtpscript
SRCS=	smtpscript.c iobuf.c parse.y
NOMAN=	noman

LDADD=		-lutil
CPPFLAGS+=	-I${.CURDIR}/..

.include <bsd.prog.mk>
