.PATH: ${.CURDIR}/.. ${.CURDIR}/../.. /usr/src/lib/libc/asr

# detect if asr is built in libc
TESTASR!=	nm `ls /usr/lib/libc.so.* | sort | tail -1` | grep "T asr_unpack_rr" | cut -d ' ' -f 3
.if ${TESTASR} != "asr_unpack_rr"
NEED_ASR=	Yes
.endif

PROG=	filter-dnsbl
SRCS=	filter_dnsbl.c
SRCS+=	asr_event.c


.ifdef NEED_ASR
SRCS+=		asr.c asr_debug.c asr_utils.c getaddrinfo_async.c	\
		res_send_async.c res_search_async.c
.endif

NOMAN=	noman

CFLAGS+=	-I/usr/src/lib/libc/asr
.ifdef NEED_ASR
CFLAGS+=	-DASR_OPT_THREADSAFE=0
.endif

.include <bsd.prog.mk>
