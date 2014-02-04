.PATH: ${.CURDIR}/.. ${.CURDIR}/../..

PROG=	filter-python2.7
SRCS=	filter_python2.7.c to.c

CFLAGS+=	-I/usr/local/include/python2.7
DPADD+=	${LIBUTIL} ${LIBPYTHON2.7}
LDADD+= ${LIBUTIL} -L/usr/local/lib -lpython2.7

NOMAN=	noman

.include <bsd.prog.mk>
