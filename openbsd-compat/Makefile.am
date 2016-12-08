noinst_LIBRARIES = libopenbsd-compat.a

libopenbsd_compat_a_SOURCES =							\
		arc4random.c base64.c 		\
		bsd-getpeereid.c bsd-misc.c bsd-waitpid.c 	\
		entropy.c errc.c event_asr_run.c explicit_bzero.c	\
		fgetln.c flock.c getopt.c imsg.c imsg-buffer.c	\
		libressl.c pidfile.c pw_dup.c reallocarray.c setresguid.c	\
		setproctitle.c strlcat.c strlcpy.c strmode.c strtonum.c		\
		strsep.c vis.c xmalloc.c

if !SUPPORT_BASENAME
libopenbsd_compat_a_SOURCES += basename.c
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

if !SUPPORT_FMT_SCALED
libopenbsd_compat_a_SOURCES += fmt_scaled.c
endif

if !SUPPORT_FPARSELN
libopenbsd_compat_a_SOURCES += fparseln.c
endif

if !SUPPORT_INET_NET_PTON
libopenbsd_compat_a_SOURCES += inet_net_pton.c
endif

EXTRA_DIST =	base64.h bsd-misc.h bsd-waitpid.h chacha_private.h defines.h	\
		entropy.h imsg.h includes.h log.h openbsd-compat.h sys/queue.h	\
		sys/tree.h vis.h xmalloc.h

AM_CPPFLAGS = -I$(top_srcdir)/smtpd -I$(top_srcdir)/openbsd-compat
