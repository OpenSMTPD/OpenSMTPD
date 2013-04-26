.PATH: ${.CURDIR}/.. ${.CURDIR}/../..

PROG=	backend-table-sqlite

SRCS=	table_sqlite.c
SRCS+=	table_api.c

NOMAN=	noman

DPADD+=	${LIBSQLITE3}
LDADD+=	-lsqlite3

.include <bsd.prog.mk>
