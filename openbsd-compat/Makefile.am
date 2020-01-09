noinst_LIBRARIES = libopenbsd.a

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/smtpd -I$(top_srcdir)/openbsd-compat

libopenbsd_a_SOURCES =	empty.c

if NEED_LIBASR
AM_CPPFLAGS += -I$(top_srcdir)/openbsd-compat/libasr

libopenbsd_a_SOURCES +=	libasr/asr.c
libopenbsd_a_SOURCES +=	libasr/asr_debug.c
libopenbsd_a_SOURCES +=	libasr/asr_compat.c
libopenbsd_a_SOURCES +=	libasr/asr_utils.c
libopenbsd_a_SOURCES +=	libasr/getaddrinfo_async.c
libopenbsd_a_SOURCES +=	libasr/gethostnamadr_async.c
libopenbsd_a_SOURCES +=	libasr/getnameinfo_async.c
libopenbsd_a_SOURCES +=	libasr/getnetnamadr_async.c
libopenbsd_a_SOURCES +=	libasr/res_search_async.c
libopenbsd_a_SOURCES +=	libasr/res_send_async.c

include_HEADERS =	libasr/asr.h
endif



if NEED_PROGNAME
libopenbsd_a_SOURCES +=	progname.c
endif

if NEED_ARC4RANDOM
libopenbsd_a_SOURCES +=	arc4random.c
endif

if NEED_BASE64
libopenbsd_a_SOURCES +=	base64.c
endif

if NEED_BASENAME
libopenbsd_a_SOURCES += basename.c
endif

if NEED_CLOCK_GETTIME
libopenbsd_a_SOURCES += clock_gettime.c
endif

if NEED_CLOSEFROM
libopenbsd_a_SOURCES += closefrom.c
endif

if NEED_CRYPT_CHECKPASS
libopenbsd_a_SOURCES += crypt_checkpass.c
endif

if NEED_DAEMON
libopenbsd_a_SOURCES += daemon.c
endif

if NEED_DIRNAME
libopenbsd_a_SOURCES += dirname.c
endif

if NEED_ERR
libopenbsd_a_SOURCES += bsd-err.c
endif

if NEED_ERRC
libopenbsd_a_SOURCES += errc.c
endif

if NEED_EVENT_ASR_RUN
libopenbsd_a_SOURCES +=	event_asr_run.c
endif

if NEED_EXPLICIT_BZERO
libopenbsd_a_SOURCES += explicit_bzero.c
endif

if NEED_FGETLN
libopenbsd_a_SOURCES +=	fgetln.c
endif

if NEED_FMT_SCALED
libopenbsd_a_SOURCES += fmt_scaled.c
endif

if NEED_FPARSELN
libopenbsd_a_SOURCES += fparseln.c
endif

if NEED_FREEZERO
libopenbsd_a_SOURCES +=	freezero.c
endif

if NEED_GETOPT
libopenbsd_a_SOURCES +=	getopt.c
endif

if NEED_GETPEEREID
libopenbsd_a_SOURCES +=	getpeereid.c
endif

if NEED_IMSG
libopenbsd_a_SOURCES +=	imsg.c
libopenbsd_a_SOURCES +=	imsg-buffer.c
endif

if NEED_INET_NET_PTON
libopenbsd_a_SOURCES += inet_net_pton.c
endif

if NEED_NANOSLEEP
libopenbsd_a_SOURCES +=	nanosleep.c
endif

if NEED_PIDFILE
libopenbsd_a_SOURCES +=	pidfile.c
endif

if NEED_REALLOCARRAY
libopenbsd_a_SOURCES +=	reallocarray.c
endif

if NEED_RECALLOCARRAY
libopenbsd_a_SOURCES +=	recallocarray.c
endif

if NEED_RES_HNOK
libopenbsd_a_SOURCES +=	res_hnok.c
endif

if NEED_RES_RANDOMID
libopenbsd_a_SOURCES +=	res_randomid.c
endif

if NEED_SETPROCTITLE
libopenbsd_a_SOURCES +=	setproctitle.c
endif

if NEED_SETRESGID
libopenbsd_a_SOURCES +=	setresgid.c
endif

if NEED_SETRESUID
libopenbsd_a_SOURCES +=	setresuid.c
endif

if NEED_SETEGID
libopenbsd_a_SOURCES +=	setegid.c
endif

if NEED_SETEUID
libopenbsd_a_SOURCES +=	seteuid.c
endif

if NEED_SIGNAL
libopenbsd_a_SOURCES +=	signal.c
endif

if NEED_SSL_CTX_USE_CERTIFICATE_CHAIN_MEM
libopenbsd_a_SOURCES +=	SSL_CTX_use_certificate_chain_mem.c
endif

if NEED_STRERROR
libopenbsd_a_SOURCES +=	strerror.c
endif

if NEED_STRLCAT
libopenbsd_a_SOURCES +=	strlcat.c
endif

if NEED_STRLCPY
libopenbsd_a_SOURCES +=	strlcpy.c
endif

if NEED_STRMODE
libopenbsd_a_SOURCES +=	strmode.c
endif

if NEED_STRSEP
libopenbsd_a_SOURCES +=	strsep.c
endif

if NEED_STRTONUM
libopenbsd_a_SOURCES +=	strtonum.c
endif

if NEED_STRNDUP
libopenbsd_a_SOURCES += strndup.c
endif

if NEED_STRNLEN
libopenbsd_a_SOURCES += strnlen.c
endif

if NEED_USLEEP
libopenbsd_a_SOURCES +=	usleep.c
endif

if NEED_VIS
libopenbsd_a_SOURCES +=	vis.c
endif

if NEED_WAITPID
libopenbsd_a_SOURCES +=	bsd-waitpid.c
endif



EXTRA_DIST =	base64.h
EXTRA_DIST +=	bsd-misc.h
EXTRA_DIST +=	bsd-waitpid.h
EXTRA_DIST +=	chacha_private.h
EXTRA_DIST +=	defines.h
EXTRA_DIST +=	entropy.h
EXTRA_DIST +=	imsg.h
EXTRA_DIST +=	includes.h
EXTRA_DIST +=	log.h
EXTRA_DIST +=	openbsd-compat.h
EXTRA_DIST +=	sys/queue.h
EXTRA_DIST +=	sys/tree.h
EXTRA_DIST +=	bsd-vis.h

if NEED_LIBASR
EXTRA_DIST +=		libasr/asr_compat.h
EXTRA_DIST +=		libasr/asr_private.h
endif


if !NEED_ERR_H
AM_CPPFLAGS += -I$(top_srcdir)/openbsd-compat/err_h
endif
