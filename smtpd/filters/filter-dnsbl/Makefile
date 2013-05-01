.PATH: ${.CURDIR}/.. ${.CURDIR}/../.. /usr/src/lib/libc/asr

PROG=	filter-dnsbl
SRCS=	filter_dnsbl.c
SRCS+=	asr_event.c

# resolver
SRCS+=		asr.c asr_debug.c asr_utils.c getaddrinfo_async.c	\
		res_send_async.c res_search_async.c

NOMAN=	noman

CFLAGS+=	-I/usr/src/lib/libc/asr
CFLAGS+=	-DASR_OPT_THREADSAFE=0

.include <bsd.prog.mk>
