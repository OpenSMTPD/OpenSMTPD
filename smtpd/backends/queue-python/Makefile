.PATH: ${.CURDIR}/.. ${.CURDIR}/../..

PROG=	queue-python

SRCS+=	queue_api.c
SRCS+=	queue_python.c

CFLAGS+=	-I/usr/local/include/python2.7
DPADD+=		${LIBUTIL} ${LIBPYTHON2.7}
LDADD+=		${LIBUTIL} -L/usr/local/lib -lpython2.7

NOMAN=	noman

.include <bsd.prog.mk>
