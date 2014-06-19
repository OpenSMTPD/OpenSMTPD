.PATH: ${.CURDIR}/.. ${.CURDIR}/../..

PROG=	scheduler-python
SRCS=	scheduler_python.c
SRCS+=	scheduler_api.c

CFLAGS+=	-I/usr/local/include/python2.7
DPADD+=	${LIBUTIL} ${LIBPYTHON2.7}
LDADD+= ${LIBUTIL} -L/usr/local/lib -lpython2.7

NOMAN=	noman

.include <bsd.prog.mk>
