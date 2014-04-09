ASRDIR=		/usr/src/lib/libc/asr
.PATH: ${.CURDIR}/.. ${.CURDIR}/../.. ${ASRDIR}

# detect if asr is built in libc
TESTASR!=	nm `ls /usr/lib/libc.so.* | sort | tail -1` | grep "T asr_run_sync" | cut -d ' ' -f 3
.if ${TESTASR} != "asr_run_sync"
NEED_ASR=	Yes
.endif

# detect if libevent has event_asr_run
TESTEVENTASRRUN!=	nm `ls /usr/lib/libevent.so.* | sort | tail -1` | grep "T event_asr_run" | cut -d ' ' -f 3
.if ${TESTEVENTASRRUN} != "event_asr_run"
NEED_EVENT_ASR_RUN=	Yes
.endif

PROG=	filter-dnsbl
SRCS=	filter_dnsbl.c

.ifdef NEED_ASR
SRCS+=		asr.c
SRCS+=		asr_debug.c
SRCS+=		asr_utils.c
SRCS+=		gethostnamadr_async.c
SRCS+=		res_send_async.c
SRCS+=		getaddrinfo_async.c
SRCS+=		getnameinfo_async.c
SRCS+=		res_search_async.c
CFLAGS+=	-I${ASRDIR}
CFLGAS+=	-DASR_OPT_THREADSAFE=0
.endif

.ifdef NEED_EVENT_ASR_RUN
SRCS+=		event_asr_run.c
CFLAGS+=	-DNEED_EVENT_ASR_RUN
.endif

NOMAN=	noman

.include <bsd.prog.mk>
