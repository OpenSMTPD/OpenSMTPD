noinst_LIBRARIES = libopenbsd-compat.a

libopenbsd_compat_a_SOURCES =							\
		base64.c basename.c bsd-arc4random.c bsd-closefrom.c		\
		bsd-getpeereid.c bsd-waitpid.c daemon.c dirname.c entropy.c	\
		fake-rfc2553.c fgetln.c getopt.c fmt_scaled.c fparseln.c imsg.c	\
		imsg-buffer.c mktemp.c setresguid.c setproctitle.c strlcat.c	\
		strlcpy.c strmode.c strtonum.c strsep.c utimes.c vis.c xmalloc.c

EXTRA_DIST =	base64.h bsd-waitpid.h defines.h entropy.h fake-rfc2553.h imsg.h\
		includes.h openbsd-compat.h sys-queue.h sys-tree.h utime.h vis.h\
		xmalloc.h

INCLUDES = -I$(top_srcdir)/src -I$(top_srcdir)/openbsd-compat
