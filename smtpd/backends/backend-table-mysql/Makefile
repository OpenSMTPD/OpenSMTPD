.PATH: ${.CURDIR}/.. ${.CURDIR}/../..

PROG=	table-mysql

SRCS=	table_mysql.c
SRCS+=	table_api.c
SRCS+=	dict.c

NOMAN=	noman

CFLAGS+=-I/usr/local/include
LDADD+=	-L/usr/local/lib -lmysqlclient

.include <bsd.prog.mk>
