noinst_LIBRARIES = libopenbsd-compat.a

libopenbsd_compat_a_SOURCES =							\
		base64.c basename.c bsd-arc4random.c bsd-closefrom.c		\
		bsd-getpeereid.c bsd-waitpid.c clock_gettime.c daemon.c		\
		dirname.c entropy.c fgetln.c getopt.c fmt_scaled.c fparseln.c	\
		imsg.c imsg-buffer.c mktemp.c setresguid.c setproctitle.c	\
		strlcat.c strlcpy.c strmode.c strtonum.c strsep.c vis.c		\
		xmalloc.c

EXTRA_DIST =	base64.h bsd-waitpid.h defines.h entropy.h imsg.h includes.h	\
		openbsd-compat.h sys-queue.h sys-tree.h vis.h xmalloc.h

INCLUDES = -I$(top_srcdir)/src -I$(top_srcdir)/openbsd-compat
