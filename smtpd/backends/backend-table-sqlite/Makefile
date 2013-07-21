.PATH: ${.CURDIR}/.. ${.CURDIR}/../..

PROG=	table-sqlite

SRCS=	table_sqlite.c
SRCS+=	table_api.c
SRCS+=	dict.c

NOMAN=	noman

DPADD+=	${LIBSQLITE3}
LDADD+=	-lsqlite3

.include <bsd.prog.mk>
