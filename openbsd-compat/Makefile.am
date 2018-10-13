noinst_LIBRARIES = libopenbsd-compat.a

libopenbsd_compat_a_SOURCES =	arc4random.c
libopenbsd_compat_a_SOURCES +=	base64.c
libopenbsd_compat_a_SOURCES +=	bsd-getpeereid.c
libopenbsd_compat_a_SOURCES +=	bsd-misc.c
libopenbsd_compat_a_SOURCES +=	bsd-waitpid.c
libopenbsd_compat_a_SOURCES +=	entropy.c
libopenbsd_compat_a_SOURCES +=	event_asr_run.c
libopenbsd_compat_a_SOURCES +=	fgetln.c
libopenbsd_compat_a_SOURCES +=	freezero.c
libopenbsd_compat_a_SOURCES +=	getopt.c
libopenbsd_compat_a_SOURCES +=	imsg.c
libopenbsd_compat_a_SOURCES +=	imsg-buffer.c
libopenbsd_compat_a_SOURCES +=	libressl.c
libopenbsd_compat_a_SOURCES +=	pidfile.c
libopenbsd_compat_a_SOURCES +=	pw_dup.c
libopenbsd_compat_a_SOURCES +=	reallocarray.c
libopenbsd_compat_a_SOURCES +=	recallocarray.c
libopenbsd_compat_a_SOURCES +=	setproctitle.c
libopenbsd_compat_a_SOURCES +=	setresguid.c
libopenbsd_compat_a_SOURCES +=	strlcat.c
libopenbsd_compat_a_SOURCES +=	strlcpy.c
libopenbsd_compat_a_SOURCES +=	strmode.c
libopenbsd_compat_a_SOURCES +=	strtonum.c
libopenbsd_compat_a_SOURCES +=	strsep.c
libopenbsd_compat_a_SOURCES +=	vis.c
libopenbsd_compat_a_SOURCES +=	xmalloc.c

if !SUPPORT_BASENAME
libopenbsd_compat_a_SOURCES += basename.c
endif

if !SUPPORT_CRYPT_CHECKPASS
libopenbsd_compat_a_SOURCES += crypt_checkpass.c
endif

if !SUPPORT_CLOCK_GETTIME
libopenbsd_compat_a_SOURCES += clock_gettime.c
endif

if !SUPPORT_CLOSEFROM
libopenbsd_compat_a_SOURCES += bsd-closefrom.c
endif

if !SUPPORT_DAEMON
libopenbsd_compat_a_SOURCES += daemon.c
endif

if !SUPPORT_DIRNAME
libopenbsd_compat_a_SOURCES += dirname.c
endif

if !SUPPORT_ERR_H
libopenbsd_compat_a_SOURCES += bsd-err.c
endif

if !SUPPORT_ERRC
libopenbsd_compat_a_SOURCES += errc.c
endif

if !SUPPORT_EXPLICIT_BZERO
libopenbsd_compat_a_SOURCES += explicit_bzero.c
endif

if !SUPPORT_FMT_SCALED
libopenbsd_compat_a_SOURCES += fmt_scaled.c
endif

if !SUPPORT_FLOCK
libopenbsd_compat_a_SOURCES += flock.c
endif

if !SUPPORT_FPARSELN
libopenbsd_compat_a_SOURCES += fparseln.c
endif

if !SUPPORT_GETLINE
libopenbsd_compat_a_SOURCES += getline.c
endif

if !SUPPORT_INET_NET_PTON
libopenbsd_compat_a_SOURCES += inet_net_pton.c
endif

if !SUPPORT_STRNDUP
libopenbsd_compat_a_SOURCES += strndup.c
endif

if !SUPPORT_STRNLEN
libopenbsd_compat_a_SOURCES += strnlen.c
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
