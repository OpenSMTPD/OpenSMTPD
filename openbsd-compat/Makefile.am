noinst_LIBRARIES = libopenbsd-compat.a

libopenbsd_compat_a_SOURCES =							\
		arc4random.c base64.c basename.c bsd-closefrom.c		\
		bsd-getpeereid.c bsd-misc.c bsd-waitpid.c clock_gettime.c	\
		daemon.c dirname.c entropy.c event_asr_run.c explicit_bzero.c	\
		fgetln.c fmt_scaled.c fparseln.c getopt.c imsg.c imsg-buffer.c	\
		mktemp.c pidfile.c pw_dup.c reallocarray.c setresguid.c		\
		setproctitle.c strlcat.c strlcpy.c strmode.c strtonum.c		\
		strsep.c vis.c xmalloc.c

EXTRA_DIST =	asr.h base64.h bsd-misc.h bsd-waitpid.h chacha_private.h	\
		defines.h entropy.h imsg.h includes.h log.h openbsd-compat.h	\
		sys/queue.h sys/tree.h vis.h xmalloc.h

AM_CPPFLAGS = -I$(top_srcdir)/smtpd -I$(top_srcdir)/openbsd-compat
