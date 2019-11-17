noinst_LIBRARIES = libopenbsd-compat.a

libopenbsd_compat_a_SOURCES =	empty.c

libopenbsd_compat_a_SOURCES +=	arc4random.c
libopenbsd_compat_a_SOURCES +=	base64.c
libopenbsd_compat_a_SOURCES +=	bsd-misc.c
libopenbsd_compat_a_SOURCES +=	bsd-waitpid.c
libopenbsd_compat_a_SOURCES +=	entropy.c
libopenbsd_compat_a_SOURCES +=	event_asr_run.c
libopenbsd_compat_a_SOURCES +=	vis.c
libopenbsd_compat_a_SOURCES +=	xmalloc.c

#if NEED_SSL_CTX_USE_CERTIFICATE_CHAIN_MEM
#libopenbsd_compat_a_SOURCES +=	SSL_CTX_use_certificate_chain_mem.c
#endif

if NEED_BASENAME
libopenbsd_compat_a_SOURCES += basename.c
endif

if NEED_CLOCK_GETTIME
libopenbsd_compat_a_SOURCES += clock_gettime.c
endif

if NEED_CLOSEFROM
libopenbsd_compat_a_SOURCES += closefrom.c
endif

if NEED_CRYPT_CHECKPASS
libopenbsd_compat_a_SOURCES += crypt_checkpass.c
endif

if NEED_DAEMON
libopenbsd_compat_a_SOURCES += daemon.c
endif

if NEED_DIRNAME
libopenbsd_compat_a_SOURCES += dirname.c
endif

if NEED_ERRC
libopenbsd_compat_a_SOURCES += errc.c
endif

if NEED_EXPLICIT_BZERO
libopenbsd_compat_a_SOURCES += explicit_bzero.c
endif

if NEED_FGETLN
libopenbsd_compat_a_SOURCES +=	fgetln.c
endif

if NEED_FMT_SCALED
libopenbsd_compat_a_SOURCES += fmt_scaled.c
endif

if NEED_FPARSELN
libopenbsd_compat_a_SOURCES += fparseln.c
endif

if NEED_FREEZERO
libopenbsd_compat_a_SOURCES +=	freezero.c
endif

if NEED_GETOPT
libopenbsd_compat_a_SOURCES +=	getopt.c
endif

if NEED_GETPEEREID
libopenbsd_compat_a_SOURCES +=	getpeereid.c
endif

if NEED_IMSG
libopenbsd_compat_a_SOURCES +=	imsg.c
libopenbsd_compat_a_SOURCES +=	imsg-buffer.c
endif

if NEED_INET_NET_PTON
libopenbsd_compat_a_SOURCES += inet_net_pton.c
endif

if NEED_PIDFILE
libopenbsd_compat_a_SOURCES +=	pidfile.c
endif

if NEED_REALLOCARRAY
libopenbsd_compat_a_SOURCES +=	reallocarray.c
endif

if NEED_RECALLOCARRAY
libopenbsd_compat_a_SOURCES +=	recallocarray.c
endif

if NEED_SETPROCTITLE
libopenbsd_compat_a_SOURCES +=	setproctitle.c
endif

if NEED_SETRESGID
libopenbsd_compat_a_SOURCES +=	setresgid.c
endif

if NEED_SETRESUID
libopenbsd_compat_a_SOURCES +=	setresuid.c
endif

if NEED_SSL_CTX_USE_CERTIFICATE_CHAIN_MEM
libopenbsd_compat_a_SOURCES +=	SSL_CTX_use_certificate_chain_mem.c
endif

if NEED_STRLCAT
libopenbsd_compat_a_SOURCES +=	strlcat.c
endif

if NEED_STRLCPY
libopenbsd_compat_a_SOURCES +=	strlcpy.c
endif

if NEED_STRMODE
libopenbsd_compat_a_SOURCES +=	strmode.c
endif

if NEED_STRSEP
libopenbsd_compat_a_SOURCES +=	strsep.c
endif

if NEED_STRTONUM
libopenbsd_compat_a_SOURCES +=	strtonum.c
endif

if NEED_STRNDUP
libopenbsd_compat_a_SOURCES += strndup.c
endif

if NEED_STRNLEN
libopenbsd_compat_a_SOURCES += strnlen.c
endif


if !SUPPORT_ERR_H
libopenbsd_compat_a_SOURCES += bsd-err.c
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
EXTRA_DIST +=	xmalloc.h

AM_CPPFLAGS = -I$(top_srcdir)/smtpd -I$(top_srcdir)/openbsd-compat
if !SUPPORT_ERR_H
AM_CPPFLAGS += -I$(top_srcdir)/openbsd-compat/err_h
endif
