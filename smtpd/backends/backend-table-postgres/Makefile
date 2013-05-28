.PATH: ${.CURDIR}/.. ${.CURDIR}/../..

PROG=	backend-table-postgres

SRCS=	table_postgres.c
SRCS+=	table_api.c
SRCS+=	dict.c

NOMAN=	noman

CFLAGS+=-I/usr/local/include
LDADD+=	-L/usr/local/lib -lpq

.include <bsd.prog.mk>
