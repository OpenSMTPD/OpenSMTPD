.PATH: ${.CURDIR}/.. ${.CURDIR}/../..

PROG=	filter-dnsbl
SRCS=	filter_dnsbl.c
SRCS+=	asr_event.c

NOMAN=	noman

CFLAGS+=	-I/usr/src/lib/libc/asr

.include <bsd.prog.mk>
