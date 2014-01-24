#	$OpenBSD$

.PATH:		${.CURDIR}/.. /usr/src/lib/libc/asr

# detect if asr is built in libc
TESTASR!=	nm `ls /usr/lib/libc.so.* | sort | tail -1` | grep "T asr_unpack_rr" | cut -d ' ' -f 3
.if ${TESTASR} != "asr_unpack_rr"
NEED_ASR=	Yes
.endif

PROG=		smtpd

SRCS=		aliases.c
SRCS+=		bounce.c
SRCS+=		ca.c
SRCS+=		compress_backend.c
SRCS+=		config.c
SRCS+=		control.c
SRCS+=		crypto.c
SRCS+=		delivery.c
SRCS+=		dict.c
SRCS+=		dns.c
SRCS+=		envelope.c
SRCS+=		esc.c
SRCS+=		expand.c
SRCS+=		forward.c
SRCS+=		iobuf.c
SRCS+=		ioev.c
SRCS+=		limit.c
SRCS+=		lka.c
SRCS+=		lka_session.c
SRCS+=		log.c
SRCS+=		mda.c
SRCS+=		mfa.c
SRCS+=		mfa_session.c
SRCS+=		mproc.c
SRCS+=		mta.c
SRCS+=		mta_session.c
SRCS+=		parse.y
SRCS+=		queue.c
SRCS+=		queue_backend.c
SRCS+=		ruleset.c
SRCS+=		runq.c
SRCS+=		scheduler.c
SRCS+=		scheduler_backend.c
SRCS+=		smtp.c
SRCS+=		smtp_session.c
SRCS+=		smtpd.c
SRCS+=		ssl.c
SRCS+=		ssl_privsep.c
SRCS+=		ssl_smtpd.c
SRCS+=		stat_backend.c
SRCS+=		table.c
SRCS+=		to.c
SRCS+=		tree.c
SRCS+=		util.c
SRCS+=		waitq.c


# backends
SRCS+=		compress_gzip.c
SRCS+=		delivery_filename.c
SRCS+=		delivery_maildir.c
SRCS+=		delivery_mbox.c
SRCS+=		delivery_mda.c
SRCS+=		delivery_lmtp.c
SRCS+=		table_db.c
SRCS+=		table_getpwnam.c
SRCS+=		table_proc.c
SRCS+=		table_static.c
SRCS+=		queue_fs.c
SRCS+=		queue_null.c
SRCS+=		queue_proc.c
SRCS+=		queue_ram.c
SRCS+=		scheduler_ramqueue.c
SRCS+=		scheduler_null.c
SRCS+=		scheduler_proc.c
SRCS+=		stat_ramstat.c

.ifdef NEED_ASR
SRCS+=		asr.c
SRCS+=		asr_debug.c
SRCS+=		asr_utils.c
SRCS+=		gethostnamadr_async.c
SRCS+=		res_send_async.c
SRCS+=		getaddrinfo_async.c
SRCS+=		getnameinfo_async.c
SRCS+=		res_search_async.c
.endif

MAN=		smtpd.8 smtpd.conf.5 table.5
BINDIR=		/usr/sbin

LDADD+=		-levent -lutil -lssl -lcrypto -lm -lz
DPADD+=		${LIBEVENT} ${LIBUTIL} ${LIBSSL} ${LIBCRYPTO} ${LIBM} ${LIBZ}
CFLAGS+=	-g3 -ggdb -I${.CURDIR}/.. -I/usr/src/lib/libc/asr
CFLAGS+=	-Wall -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=	-Wmissing-declarations
CFLAGS+=	-Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+=	-Wsign-compare -Wbounded
#CFLAGS+=	-Werror # during development phase (breaks some archs)
CFLAGS+=	-DIO_SSL
CFLAGS+=	-DQUEUE_PROFILING
.ifdef NEED_ASR
CFLAGS+=	-DASR_OPT_THREADSAFE=0
.endif
YFLAGS=

.include <bsd.prog.mk>
