# Copyright (c) 2023 Omar Polo <op@openbsd.org>
# Copyright (c) 2016 Gilles Chehade <gilles@poolp.org>
# Copyright (c) 1999-2004 Damien Miller
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

AC_INIT([OpenSMTPD-portable], [7.7.0p0], [bugs@opensmtpd.org],
    [opensmtpd], [https://www.opensmtpd.org])

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_LIBOBJ_DIR([openbsd-compat])
AC_CANONICAL_HOST
AM_INIT_AUTOMAKE([-Wall foreign subdir-objects])

AC_USE_SYSTEM_EXTENSIONS

AM_PROG_AR
AC_PROG_CC
AC_C_INLINE
AC_PROG_INSTALL
AC_PROG_EGREP
PKG_PROG_PKG_CONFIG
AC_PROG_YACC

LT_INIT

AC_PATH_PROG([CAT], [cat])
AC_PATH_PROG([CHMOD], [chmod])
AC_PATH_PROG([CHOWN], [chown])
AC_PATH_PROG([ZCAT], [zcat])
AC_PATH_PROG([SED], [sed])

# use libbsd by default; these needs to precede any other check, as we
# might not need a compat function when using libbsd.
AC_ARG_WITH([libbsd],
    AS_HELP_STRING([--without-libbsd], [Disable libbsd usage]))
AS_IF([test "x$with_libbsd" != xno], [
	PKG_CHECK_MODULES([LIBBSD], [libbsd-overlay libbsd-ctor], [
		CFLAGS="$LIBBSD_CFLAGS $CFLAGS"
		LDFLAGS="$LIBBSD_LIBS $LDFLAGS"
	], [AS_IF([test "x$with_libbsd" = "xyes"], [
		AC_MSG_ERROR([libbsd requested but not found])
	])])
])

need_dash_r=
need_libasr=yes
pkglibexecdir="$libexecdir/opensmtpd"
AS_CASE(["$host"],
	[*-*-darwin*], [
		use_pie=auto
		AC_DEFINE([SETEUID_BREAKS_SETUID], [1],
			[define if seteuid breaks setuid])
		AC_DEFINE([BROKEN_SETREUID], [1],
			[define if setreuid is broken])
		AC_DEFINE([BROKEN_SETREGID], [1],
			[define if setregid is broken])
		AC_DEFINE([SPT_TYPE], [SPT_REUSEARGV],
			[Define to a Set Process Title type if your system is
			supported by bsd-setproctitle.c])
],
	[*-*-linux* | *-gnu* | *-k*bsd*-gnu*], [
		use_pie=auto
		AC_DEFINE([SPT_TYPE], [SPT_REUSEARGV])
],
	[*-*-netbsd*], [
		need_dash_r=yes
		AM_CFLAGS="$AM_CFLAGS -D_OPENBSD_SOURCE"
],
	[*-*-openbsd*], [
		use_pie=auto
		need_libasr=no
		pkglibexecdir="$libexecdir/smtpd"
		AC_DEFINE([HAVE_ATTRIBUTE__SENTINEL__], [1],
			[OpenBSD's gcc has sentinel])
		AC_DEFINE([HAVE_ATTRIBUTE__BOUNDED__], [1],
			[OpenBSD's gcc has bounded])
		AC_DEFINE([NOOP_ASR_FREEADDRINFO], [0],
			[OpenBSD doesn't need ASR_FREEADDRINFO])
],
	[*-sun-solaris*], [
		AC_DEFINE([HAVE_M_DATA], [1],
			[M_DATA is defined in sys/stream.h included by netinet/in.h])
])
AC_SUBST([pkglibexecdir])

# XXX arc4random is checked later since some old (pre 3.8) versions of
# LibreSSL provide this symbol mistakenly.
AC_REPLACE_FUNCS([ \
	basename \
	clock_gettime \
	closefrom \
	crypt_checkpass \
	daemon \
	dirname \
	errc \
	explicit_bzero \
	fgetln \
	freezero \
	getdtablecount \
	getdtablesize \
	getopt \
	getpeereid \
	nanosleep \
	pipe2 \
	reallocarray \
	recallocarray \
	res_hnok \
	seteuid \
	setegid \
	setproctitle \
	setresuid \
	setresgid \
	signal \
	strlcpy \
	strlcat \
	strmode \
	strndup \
	strnlen \
	strsep \
	strtonum \
	timingsafe_memcmp \
	usleep \
])
# TODO: add vasprintf to the above

AC_CHECK_FUNCS([ \
	dirfd \
	getpeerucred \
	getspnam \
	malloc_conceal \
	pledge \
	setreuid \
	setsid \
	sigaction \
	strnvis \
	sysconf \
])

AC_CHECK_HEADERS([ \
	arpa/nameser_compat.h \
	crypt.h \
	dirent.h \
	endian.h \
	fcntl.h \
	libkern/OSByteOrder.h \
	libutil.h \
	limits.h \
	login_cap.h \
	mach/mach_time.h \
	maillock.h \
	ndir.h \
	netdb.h \
	pam/pam_appl.h \
	paths.h \
	security/pam_appl.h \
	shadow.h \
	sys/bitypes.h \
	sys/dir.h \
	sys/endian.h \
	sys/file.h \
	sys/mount.h \
	sys/ndir.h \
	sys/pstat.h \
	sys/statfs.h \
	sys/statvfs.h \
	sys/time.h \
	sys/un.h \
	ucred.h \
	util.h \
	vis.h \
])

AS_IF([test "x$need_libasr" = xyes], [
	AM_CFLAGS="$AM_CFLAGS -I\${top_srcdir}/openbsd-compat/libasr"
])
AM_CONDITIONAL([NEED_LIBASR], [test "x$need_libasr" = xyes])

AS_IF([test "x$ac_cv_func_errc" = xno], [
	AM_CFLAGS="$AM_CFLAGS -I\${top_srcdir}/openbsd-compat/err_h"
])

AS_IF([test "x$ac_cv_header_paths_h" = xno], [
	AM_CFLAGS="$AM_CFLAGS -I\${top_srcdir}/openbsd-compat/paths_h"
])

# check for functions that may be provided by a library; need to do
# this *after* the libc/libbsd things to avoid picking up unwanted
# symbols from libraries.

AC_SEARCH_LIBS([basename], [gen],
	[AC_DEFINE([HAVE_BASENAME], 1, [1 if have basename])],
	[AC_LIBOBJ([basename])])

AC_SEARCH_LIBS([clock_gettime], [rt],
	[AC_DEFINE([HAVE_CLOCK_GETTIME], 1, [1 if have clock_gettime])],
	[AC_LIBOBJ([clock_gettime])])

AC_SEARCH_LIBS([closefrom], [gen], [
	AC_DEFINE([HAVE_CLOSEFROM], 1, [1 if have closefrom])
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[int r = closefrom(0);]])], [
		AC_DEFINE([HAVE_CLOSEFROM_INT], 1, [closefrom returns an int])
	])
], [AC_LIBOBJ([closefrom])])

AC_SEARCH_LIBS([crypt], [crypt],
	[AC_DEFINE([HAVE_CRYPT], 1, [1 if have crypt])])

AC_SEARCH_LIBS([crypt_gensalt], [crypt],
	[AC_DEFINE([HAVE_CRYPT_GENSALT], 1, [1 if have crypt_gensalt])])

AC_SEARCH_LIBS([dirname], [gen],
	[AC_DEFINE([HAVE_DIRNAME], 1, [1 if have dirname])],
	[AC_LIBOBJ([dirname])])

AC_SEARCH_LIBS([fmt_scaled], [util],
	[AC_DEFINE([HAVE_FMT_SCALED], 1, [1 if have fmt_scaled])],
	[AC_LIBOBJ([fmt_scaled])])

AC_SEARCH_LIBS([fparseln], [util],
	[AC_DEFINE([HAVE_FPARSELN], 1, [1 if have fparseln])],
	[AC_LIBOBJ([fparseln])])

AC_SEARCH_LIBS([fts_open], [fts],
	[AC_DEFINE([HAVE_FTS_OPEN], 1, [1 if have fts_open])],
	[AC_MSG_ERROR([can't find fts_open(); please install libfts])])

AC_SEARCH_LIBS([inet_net_pton], [resorv],
	[AC_DEFINE([HAVE_INET_NET_PTON], 1, [1 if have inet_net_pton])],
	[AC_LIBOBJ([inet_net_pton])])

AC_SEARCH_LIBS([imsg_init], [util imsg],
	[AC_DEFINE([HAVE_IMSG_INIT], 1, [1 if have imsg_init])], [
	AC_LIBOBJ([imsg])
	AC_LIBOBJ([imsg-buffer])
])

AC_SEARCH_LIBS([pidfile], [util],
	[AC_DEFINE([HAVE_PIDFILE], 1, [1 if have pidfile])],
	[AC_LIBOBJ([pidfile])])

AC_SEARCH_LIBS([res_hnok], [resolv],
	[AC_DEFINE([HAVE_RES_HNOK], 1, [1 if have res_hnok])],
	[
		dnl darwin (at least) has res_9_hnok plus #defines
		dnl to "rename" it to res_hnok.
		AC_SEARCH_LIBS([res_9_hnok], [resolv], [
			AC_DEFINE([HAVE_RES_HNOK], 1, [1 if have res_hnok])
			AC_LIBOBJ([res_hnok])
		])
	])

AC_SEARCH_LIBS([res_randomid], [resolv],
	[AC_DEFINE([HAVE_RES_RANDOMID], 1, [1 if have res_randomid])],
	[AC_LIBOBJ([res_random])])

AC_SEARCH_LIBS([setsockopt], [socket], [:],
	[AC_MSG_ERROR([can't find setsockopt])])

AC_SEARCH_LIBS([__b64_pton], [resolv],
	[AC_DEFINE([HAVE___B64_PTON], 1, [1 if have __b64_pton])])
AC_SEARCH_LIBS([b64_pton], [resolv],
	[AC_DEFINE([HAVE_b64_PTON], 1, [1 if have b64_pton])])
AC_SEARCH_LIBS([__b64_ntop], [resolv],
	[AC_DEFINE([HAVE___B64_NTOP], 1, [1 if have __b64_ntop])])
AC_SEARCH_LIBS([b64_ntop], [resolv],
	[AC_DEFINE([HAVE_b64_NTOP], 1, [1 if have b64_ntop])])

dnl darwin (at least) has these plus #defines in resolv.h
AC_SEARCH_LIBS([res_9_b64_pton], [resolv],
	[AC_DEFINE([HAVE_RES_9_B64_PTON], 1, [1 if have res_9_b64_pton])])
AC_SEARCH_LIBS([res_9_b64_ntop], [resolv],
	[AC_DEFINE([HAVE_RES_9_B64_NTOP], 1, [1 if have res_9_b64_ntop])])

AS_IF([test "x$ac_cv_search_b64_ntop" = "xno" -a \
    "x$ac_cv_search___b64_ntop" = "xno" -a \
    "x$ac_cv_search_res_9_b64_pton" = "xno" -a \
    "x$ac_cv_search_res_9_b64_ntop" = "xno"], [
	AC_LIBOBJ([base64])
])

dnl NetBSD added an strnvis and unfortunately made it incompatible with the
dnl existing one in OpenBSD and Linux's libbsd (the former having existed
dnl for over ten years). Despite this incompatibility being reported during
dnl development (see http://gnats.netbsd.org/44977) they still shipped it.
dnl Even more unfortunately FreeBSD and later MacOS picked up this incompatible
dnl implementation.
dnl
dnl OpenBSD, 2001: strnvis(char *dst, const char *src, size_t dlen, int flag);
dnl NetBSD,  2012: strnvis(char *dst, size_t dlen, const char *src, int flag);
AS_IF([test "x$ac_cv_func_strnvis" = xyes], [
	AC_MSG_CHECKING([for broken strnvis])

	saved_CFLAGS="$CFLAGS"
	CFLAGS="$CFLAGS -Wall -Werror"
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <stdio.h>
#include <stdlib.h>
#include <vis.h>
	]], [[
char buf[128];
return (strnvis(buf, "Hello, world!\n", sizeof(buf), 0));
	]])], [
		AC_MSG_RESULT([no])
	], [
		AC_MSG_RESULT([yes])
		AC_DEFINE([BROKEN_STRNVIS], [1],[argument order is swapped])
		AC_LIBOBJ([vis])
	])
	CFLAGS="$saved_CFLAGS"
])
AS_IF([test "x$ac_cv_func_strnvis" = xno], [AC_LIBOBJ([vis])])

AC_MSG_CHECKING([for /proc/pid/fd directory])
AS_IF([test -d "/proc/$$/fd"], [
	AC_DEFINE([HAVE_PROC_PID], [1], [Define if you have /proc/pid/fd])
	AC_MSG_RESULT([yes])
], [
	AC_MSG_RESULT([no])
])

AC_CHECK_TYPES([long long, unsigned long long, long double, u_int, u_char])
AC_CHECK_SIZEOF([short int], [2])
AC_CHECK_SIZEOF([int], [4])
AC_CHECK_SIZEOF([long int], [4])
AC_CHECK_SIZEOF([long long int], [8])

AC_TYPE_INT8_T
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_INTPTR_T
AC_TYPE_INTMAX_T
AC_TYPE_UINTPTR_T
AC_TYPE_UINTMAX_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_OFF_T
AC_TYPE_MODE_T
AC_TYPE_PID_T
AC_TYPE_UID_T

TYPE_SOCKLEN_T

AC_CHECK_TYPES([sig_atomic_t], [], [], [
#include <signal.h>
])
AC_CHECK_TYPES([fsblkcnt_t, fsfilcnt_t], [], [], [
#include <sys/types.h>
#ifdef HAVE_SYS_BITYPES_H
#include <sys/bitypes.h>
#endif
#ifdef HAVE_SYS_STATFS_H
#include <sys/statfs.h>
#endif
#ifdef HAVE_SYS_STATVFS_H
#include <sys/statvfs.h>
#endif
])

AC_CHECK_TYPES([in_addr_t, in_port_t], [], [], [
#include <sys/types.h>
#include <netinet/in.h>
])

AC_CHECK_TYPES([sa_family_t], [], [], [
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
])

AC_CHECK_TYPES([struct timespec])
AC_CHECK_TYPES([struct ifgroupreq])
AC_CHECK_TYPES([struct sockaddr_storage], [], [], [
#include <sys/types.h>
#include <sys/socket.h>
])
AC_CHECK_TYPES([struct sockaddr_in6], [], [], [
#include <sys/types.h>
#include <netinet/in.h>
])
AC_CHECK_TYPES([struct in6_addr], [], [], [
#include <sys/types.h>
#include <netinet/in.h>
])
AC_CHECK_TYPES([struct addrinfo], [], [], [
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
])
AC_CHECK_TYPES([struct timeval], [], [], [
#include <sys/time.h>
])
AC_CHECK_MEMBERS([struct sockaddr_in6.sin6_scope_id], [], [], [
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#include <netinet/in.h>
])

AC_CHECK_MEMBERS([struct passwd.pw_gecos, struct passwd.pw_class,
struct passwd.pw_change, struct passwd.pw_expire],
[], [], [
#include <sys/types.h>
#include <pwd.h>
])

AC_CHECK_MEMBERS([struct stat.st_flags], , ,
	[ #include <sys/types.h>
	  #include <sys/stat.h> ]
)

AC_CHECK_MEMBERS([struct stat.st_mtim], , ,
	[ #include <sys/types.h>
	  #include <sys/stat.h> ]
)

AC_CHECK_MEMBERS([struct stat.st_mtimespec], , ,
	[ #include <sys/types.h>
	  #include <sys/stat.h> ]
)

AC_CHECK_MEMBERS([struct sockaddr.sa_len], , ,
	[ #include <netdb.h>
	  #include <netinet/in.h>
	  #include <sys/socket.h> ]
)

AC_CHECK_MEMBERS([struct sockaddr_storage.ss_len], , ,
	[ #include <netdb.h>
	  #include <netinet/in.h>
	  #include <sys/socket.h> ]
)

AC_CHECK_MEMBERS([struct sockaddr_in.sin_len], , ,
	[ #include <netdb.h>
	  #include <netinet/in.h>
	  #include <sys/socket.h> ]
)

AC_CHECK_MEMBERS([struct sockaddr_in6.sin6_len], , ,
	[ #include <netdb.h>
	  #include <netinet/in.h>
	  #include <sys/socket.h> ]
)

AC_CHECK_MEMBERS([struct statfs.f_favail], , ,
	[ #include <sys/vfs.h>
	  #include <sys/statfs.h> ]
)

AC_CHECK_MEMBERS([struct sockaddr_storage.ss_family], [], [], [
#include <sys/types.h>
#include <sys/socket.h>
])

AC_CHECK_MEMBERS([struct sockaddr_storage.__ss_family], [], [], [
#include <sys/types.h>
#include <sys/socket.h>
])

AC_CHECK_MEMBERS([struct tm.tm_gmtoff, struct tm.tm_zone], [],
	[
		AC_CHECK_DECLS([timezone, altzone, tzname],
			[],
			[ AC_MSG_ERROR([cannot find timezone])],
			[ #include <time.h> ]
		)
	],
	[ #include <time.h> ]
)

AC_CHECK_MEMBERS([struct DIR.d_type], [], [], [
#include <sys/types.h>
#include <dirent.h>
])
AC_CHECK_DECLS([O_NONBLOCK], [], [], [
#include <sys/types.h>
#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif
#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif
])

AC_CHECK_DECLS([AF_LOCAL, PF_LOCAL], [], [], [
#include <sys/socket.h>
])

AC_CHECK_DECLS([IPPORT_HILASTAUTO], [], [], [
#include <netinet/in.h>
])

AC_CHECK_DECLS([IPV6_ADDR_SCOPE_INTFACELOCAL], [], [], [
#include <netinet6/in6.h>
#include <netinet/in.h>
])

AC_CHECK_DECLS([WAIT_MYPGRP], [], [], [
#include <sys/wait.h>
])

AC_CHECK_DECLS([LOG_PERROR], [], [], [
#include <syslog.h>
])

###
### EVERYTHING BELOW MUST BE CLEANED AND MOVED ABOVE
###

#l150 (without _FORTIFY_SOURCE=2)
if test "$GCC" = "yes" -o "$GCC" = "egcs"; then
	OSSH_CHECK_CFLAG_COMPILE([-Qunused-arguments])
	OSSH_CHECK_CFLAG_COMPILE([-Wunknown-warning-option])
	OSSH_CHECK_CFLAG_COMPILE([-Wall])
	OSSH_CHECK_CFLAG_COMPILE([-Wpointer-arith])
	OSSH_CHECK_CFLAG_COMPILE([-Wuninitialized])
	OSSH_CHECK_CFLAG_COMPILE([-Wsign-compare])
	OSSH_CHECK_CFLAG_COMPILE([-Wformat-security])
	OSSH_CHECK_CFLAG_COMPILE([-Wsizeof-pointer-memaccess])
	OSSH_CHECK_CFLAG_COMPILE([-Wpointer-sign], [-Wno-pointer-sign])
	OSSH_CHECK_CFLAG_COMPILE([-Wunused-result], [-Wno-unused-result])
	OSSH_CHECK_CFLAG_COMPILE([-fno-strict-aliasing])
#	OSSH_CHECK_CFLAG_COMPILE([-D_FORTIFY_SOURCE=2])
    if test "x$use_toolchain_hardening" = "x1"; then
	OSSH_CHECK_LDFLAG_LINK([-Wl,-z,relro])
	OSSH_CHECK_LDFLAG_LINK([-Wl,-z,now])
	OSSH_CHECK_LDFLAG_LINK([-Wl,-z,noexecstack])
	# NB. -ftrapv expects certain support functions to be present in
	# the compiler library (libgcc or similar) to detect integer operations
	# that can overflow. We must check that the result of enabling it
	# actually links. The test program compiled/linked includes a number
	# of integer operations that should exercise this.
	OSSH_CHECK_CFLAG_LINK([-ftrapv])
    fi
	AC_MSG_CHECKING([gcc version])
	GCC_VER=`$CC -v 2>&1 | $AWK '/gcc version /{print $3}'`
	case $GCC_VER in
		1.*) no_attrib_nonnull=1 ;;
		2.8* | 2.9*)
		     no_attrib_nonnull=1
		     ;;
		2.*) no_attrib_nonnull=1 ;;
		*) ;;
	esac
	AC_MSG_RESULT([$GCC_VER])

	AC_MSG_CHECKING([if $CC accepts -fno-builtin-memset])
	saved_CFLAGS="$CFLAGS"
	CFLAGS="$CFLAGS -fno-builtin-memset"
	AC_LINK_IFELSE([AC_LANG_PROGRAM([[ #include <string.h> ]],
			[[ char b[10]; memset(b, 0, sizeof(b)); ]])],
		[ AC_MSG_RESULT([yes]) ],
		[ AC_MSG_RESULT([no])
		  CFLAGS="$saved_CFLAGS" ]
	)

	# -fstack-protector-all doesn't always work for some GCC versions
	# and/or platforms, so we test if we can.  If it's not supported
	# on a given platform gcc will emit a warning so we use -Werror.
	if test "x$use_stack_protector" = "x1"; then
	    for t in -fstack-protector-strong -fstack-protector-all \
		    -fstack-protector; do
		AC_MSG_CHECKING([if $CC supports $t])
		saved_CFLAGS="$CFLAGS"
		saved_LDFLAGS="$LDFLAGS"
		CFLAGS="$CFLAGS $t -Werror"
		LDFLAGS="$LDFLAGS $t -Werror"
		AC_LINK_IFELSE(
			[AC_LANG_PROGRAM([[ #include <stdio.h> ]],
			[[
	char x[256];
	snprintf(x, sizeof(x), "XXX");
			 ]])],
		    [ AC_MSG_RESULT([yes])
		      CFLAGS="$saved_CFLAGS $t"
		      LDFLAGS="$saved_LDFLAGS $t"
		      AC_MSG_CHECKING([if $t works])
		      AC_RUN_IFELSE(
			[AC_LANG_PROGRAM([[ #include <stdio.h> ]],
			[[
	char x[256];
	snprintf(x, sizeof(x), "XXX");
			]])],
			[ AC_MSG_RESULT([yes])
			  break ],
			[ AC_MSG_RESULT([no]) ],
			[ AC_MSG_WARN([cross compiling: cannot test])
			  break ]
		      )
		    ],
		    [ AC_MSG_RESULT([no]) ]
		)
		CFLAGS="$saved_CFLAGS"
		LDFLAGS="$saved_LDFLAGS"
	    done
	fi

	if test -z "$have_llong_max"; then
		# retry LLONG_MAX with -std=gnu99, needed on some Linuxes
		unset ac_cv_have_decl_LLONG_MAX
		saved_CFLAGS="$CFLAGS"
		CFLAGS="$CFLAGS -std=gnu99"
		AC_CHECK_DECL([LLONG_MAX],
		    [have_llong_max=1],
		    [CFLAGS="$saved_CFLAGS"],
		    [#include <limits.h>]
		)
	fi
fi

AC_MSG_CHECKING([if compiler allows __attribute__ on return types])
AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM([[
#include <stdlib.h>
__attribute__((__unused__)) static void foo(void){return;}]],
    [[ exit(0); ]])],
    [ AC_MSG_RESULT([yes]) ],
    [ AC_MSG_RESULT([no])
      AC_DEFINE(NO_ATTRIBUTE_ON_RETURN_TYPE, 1,
	 [compiler does not accept __attribute__ on return types]) ]
)

if test "x$no_attrib_nonnull" != "x1"; then
	AC_DEFINE([HAVE_ATTRIBUTE__NONNULL__], [1], [Have attribute nonnull])
fi

AC_ARG_WITH([rpath],
	[  --without-rpath		Disable auto-added -R linker paths],
	AS_CASE(["$withval"],
	[yes], [need_dash_r=yes],
	[no], [need_dash_r='']
))

AC_ARG_WITH([cflags],
	[  --with-cflags			Specify additional flags to pass to compiler],
	[
		if test -n "$withval" -a "$withval" != "no" -a "${withval}" != "yes"; then
			CFLAGS="$CFLAGS $withval"
		fi
	]
)
AC_ARG_WITH([cppflags],
	[  --with-cppflags		Specify additional flags to pass to preprocessor] ,
	[
		if test -n "$withval" -a "$withval" != "no" -a "${withval}" != "yes"; then
			CPPFLAGS="$CPPFLAGS $withval"
		fi
	]
)
AC_ARG_WITH([ldflags],
	[  --with-ldflags		Specify additional flags to pass to linker],
	[
		if test -n "$withval" -a "$withval" != "xno" -a "${withval}" != "yes"; then
			LDFLAGS="$LDFLAGS $withval"
		fi
	]
)

werror_flags=
AC_ARG_WITH([Werror],
	[  --with-Werror			Build main code with -Werror],
	[
		if test -n "$withval" -a "$withval" != "no"; then
			werror_flags="-Werror"
			if test "${withval}" != "yes"; then
				werror_flags="$withval"
			fi
		fi
	]
)

AC_ARG_WITH([pie],
    [  --with-pie			Build Position Independent Executables if possible], [
	if test "x$withval" = "xno"; then
		use_pie=no
	fi
	if test "x$withval" = "xyes"; then
		use_pie=yes
	fi
    ]
)
if test -z "$use_pie"; then
	use_pie=no
fi
if test "x$use_toolchain_hardening" != "x1" -a "x$use_pie" = "xauto"; then
	# Turn off automatic PIE when toolchain hardening is off.
	use_pie=no
fi
if test "x$use_pie" = "xauto"; then
	# Automatic PIE requires gcc >= 4.x
	AC_MSG_CHECKING([for gcc >= 4.x])
	AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
#if !defined(__GNUC__) || __GNUC__ < 4
#error gcc is too old
#endif
]])],
	[ AC_MSG_RESULT([yes]) ],
	[ AC_MSG_RESULT([no])
	  use_pie=no ]
)
fi
if test "x$use_pie" != "xno"; then
	SAVED_CFLAGS="$CFLAGS"
	SAVED_LDFLAGS="$LDFLAGS"
	OSSH_CHECK_CFLAG_COMPILE([-fPIE])
	OSSH_CHECK_LDFLAG_LINK([-pie])
	# We use both -fPIE and -pie or neither.
	AC_MSG_CHECKING([whether both -fPIE and -pie are supported])
	if echo "x $CFLAGS"  | grep ' -fPIE' >/dev/null 2>&1 && \
	   echo "x $LDFLAGS" | grep ' -pie'  >/dev/null 2>&1 ; then
		AC_MSG_RESULT([yes])
	else
		AC_MSG_RESULT([no])
		CFLAGS="$SAVED_CFLAGS"
		LDFLAGS="$SAVED_LDFLAGS"
	fi
fi

# Man pages defaults to mandoc
MANTYPE=doc
AC_ARG_WITH([mantype],
	[  --with-mantype=man|cat|doc   Set man page type],
	[
		case "$withval" in
		man|cat|doc)
			MANTYPE=$withval
			;;
		*)
			AC_MSG_ERROR([invalid man type: $withval])
			;;
		esac
	]
)
AC_SUBST([MANTYPE])
if test "$MANTYPE" = "doc"; then
	mansubdir=man;
else
	mansubdir=$MANTYPE;
fi
AC_SUBST([mansubdir])

# Whether to enable BSD auth support
AC_ARG_WITH([auth-bsdauth],
	[  --with-auth-bsdauth		Enable bsd_auth(3) authentication support],
	[
		if test "x$withval" != "xno"; then
			AC_DEFINE([BSD_AUTH], [1],
				[Define if you have BSD auth support])
			BSD_AUTH_MSG=yes
		fi
	]
)

PAM_MSG="no"
USE_PAM_SERVICE=smtpd
AC_ARG_WITH([auth-pam],
	[  --with-auth-pam=SERVICE	Enable PAM authentication support (default=smtpd)],
	[
		if test "x$withval" != "xno"; then
			if test -n "$withval" -a "x${withval}" != "xyes"; then
				USE_PAM_SERVICE=$withval
			fi

			if test "x$ac_cv_header_security_pam_appl_h" != "xyes" && \
			   test "x$ac_cv_header_pam_pam_appl_h" != "xyes"; then
				AC_MSG_ERROR([PAM headers not found])
			fi

			saved_LIBS="$LIBS"
			AC_CHECK_LIB([dl], [dlopen], , )
			AC_CHECK_LIB([pam], [pam_set_item], , [AC_MSG_ERROR([*** libpam missing])])
			AC_CHECK_FUNCS([pam_getenvlist])
			AC_CHECK_FUNCS([pam_putenv])
			LIBS="$saved_LIBS"

			PAM_MSG="yes"

			SMTPDLIBS="$SMTPDLIBS -lpam"
			AC_DEFINE([USE_PAM], [1],
				[Define if you want to enable PAM support])

			if test "x$ac_cv_lib_dl_dlopen" = "xyes"; then
				case "$LIBS" in
				*-ldl*)
					# libdl already in LIBS
					;;
				*)
					SMTPDLIBS="$SMTPDLIBS -ldl"
					;;
				esac
			fi
		fi
	]
)
AC_DEFINE_UNQUOTED([USE_PAM_SERVICE], ["$USE_PAM_SERVICE"], [pam service])
AC_SUBST([USE_PAM_SERVICE])


# Check for older PAM
if test "x$PAM_MSG" = "xyes"; then
	# Check PAM strerror arguments (old PAM)
	AC_MSG_CHECKING([whether pam_strerror takes only one argument])
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <stdlib.h>
#if defined(HAVE_SECURITY_PAM_APPL_H)
#include <security/pam_appl.h>
#elif defined (HAVE_PAM_PAM_APPL_H)
#include <pam/pam_appl.h>
#endif
		]], [[
(void)pam_strerror((pam_handle_t *)NULL, -1);
		]])], [AC_MSG_RESULT([no])], [
			AC_DEFINE([HAVE_OLD_PAM], [1],
				[Define if you have an old version of PAM
				which takes only one argument to pam_strerror])
			AC_MSG_RESULT([yes])
			PAM_MSG="yes (old library)"
	])
fi

SMTPD_USER=_smtpd
AC_ARG_WITH([user-smtpd],
	[  --with-user-smtpd=user	Specify non-privileged user for smtpd (default=_smtpd)],
	[
		if test -n "$withval" -a "$withval" != "no" -a "${withval}" != "yes"; then
			SMTPD_USER=$withval
		fi
	]
)
AC_DEFINE_UNQUOTED([SMTPD_USER], ["$SMTPD_USER"],
	[non-privileged user for privilege separation])
AC_SUBST([SMTPD_USER])

SMTPD_QUEUE_USER=_smtpq
AC_ARG_WITH([user-queue],
	[  --with-user-queue=user	Specify non-privileged user for queue process (default=_smtpq)],
	[
		if test -n "$withval" -a "$withval" != "no" -a "${withval}" != "yes"; then
			SMTPD_QUEUE_USER=$withval
		fi
	]
)
AC_DEFINE_UNQUOTED([SMTPD_QUEUE_USER], ["$SMTPD_QUEUE_USER"],
	[non-privileged user for queue process])
AC_SUBST([SMTPD_QUEUE_USER])

SMTPD_QUEUE_GROUP=_smtpq
AC_ARG_WITH([group-queue],
	[  --with-group-queue=group	Specify non-privileged group for offline queue (default=_smtpq)],
	[
		if test -n "$withval"  -a "$withval" != "no" -a "${withval}" != "yes"; then
			SMTPD_QUEUE_GROUP=$withval
		fi
	]
)
AC_DEFINE_UNQUOTED([SMTPD_QUEUE_GROUP], ["$SMTPD_QUEUE_GROUP"],
	[non-privileged group for queue process])
AC_SUBST([SMTPD_QUEUE_GROUP])

# Where to place spooler
spooldir=/var/spool/smtpd
AC_ARG_WITH([path-queue],
	[  --with-path-queue=PATH	Specify path to queue directory (default=/var/spool/smtpd)],
	[
		if test -n "$withval" -a "$withval" != "no" -a "${withval}" != "yes"; then
			spooldir=$withval
			if test ! -d $spooldir; then
			AC_MSG_WARN([** no $spooldir directory on this system **])
			fi
		fi
	]
)

AC_DEFINE_UNQUOTED([PATH_SPOOL], ["$spooldir"],
	[Specify location of spooler])
AC_SUBST([spooldir])


PRIVSEP_PATH=/var/empty
AC_ARG_WITH([path-empty],
	[  --with-path-empty=PATH	Specify path to empty directory (default=/var/empty)],
	[
		if test -n "$withval" -a "$withval" != "no" -a "${withval}" != "yes"; then
			PRIVSEP_PATH=$withval
		fi
	]
)
AC_SUBST([PRIVSEP_PATH])

dnl # --with-maildir=/path/to/mail gets top priority.
dnl # if maildir is set in the platform case statement above we use that.
dnl # Otherwise we run a program to get the dir from system headers.
dnl # We first look for _PATH_MAILDIR then MAILDIR then _PATH_MAIL
dnl # If we find _PATH_MAILDIR we do nothing because that is what
dnl # session.c expects anyway. Otherwise we set to the value found
dnl # stripping any trailing slash. If for some strage reason our program
dnl # does not find what it needs, we default to /var/spool/mail.
# Check for mail directory
AC_ARG_WITH([path-mbox],
    [  --with-path-mbox=PATH		Specify path to mbox directory (default=/var/spool/mail)],
    [
	if test -n "$withval" -a "$withval" != "no" -a "${withval}" != "yes"; then
		AC_DEFINE_UNQUOTED([MAIL_DIRECTORY], ["$withval"],
            [Set this to your mail directory if you do not have _PATH_MAILDIR])
	    fi
     ],[
	if test -n "$maildir"; then
	    AC_DEFINE_UNQUOTED([MAIL_DIRECTORY], ["$maildir"])
	else
	    AC_MSG_CHECKING([system mail directory])
	    AC_RUN_IFELSE(
		[AC_LANG_PROGRAM([[
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifdef HAVE_PATHS_H
#include <paths.h>
#endif
#ifdef HAVE_MAILLOCK_H
#include <maillock.h>
#endif
#define DATA "conftest.maildir"
	]], [[
	FILE *fd;
	int rc;

	fd = fopen(DATA,"w");
	if(fd == NULL)
		exit(1);

#if defined (_PATH_MAILDIR)
	if ((rc = fprintf(fd ,"_PATH_MAILDIR:%s\n", _PATH_MAILDIR)) <0)
		exit(1);
#elif defined (MAILDIR)
	if ((rc = fprintf(fd ,"MAILDIR:%s\n", MAILDIR)) <0)
		exit(1);
#elif defined (_PATH_MAIL)
	if ((rc = fprintf(fd ,"_PATH_MAIL:%s\n", _PATH_MAIL)) <0)
		exit(1);
#else
	exit (2);
#endif

	exit(0);
		]])],
		[
	 	    maildir_what=`awk -F: '{print $1}' conftest.maildir`
		    maildir=`awk -F: '{print $2}' conftest.maildir \
			| sed 's|/$||'`
		    AC_MSG_RESULT([$maildir from $maildir_what])
		    if test "x$maildir_what" != "x_PATH_MAILDIR"; then
			AC_DEFINE_UNQUOTED([MAIL_DIRECTORY], ["$maildir"])
		    fi
		],
		[
		    if test "X$ac_status" = "X2"; then
# our test program didn't find it. Default to /var/spool/mail
			AC_MSG_RESULT([/var/spool/mail])
			AC_DEFINE_UNQUOTED([MAIL_DIRECTORY], ["/var/spool/mail"])
		     else
			AC_MSG_RESULT([*** not found ***])
		     fi
		],
		[
			AC_MSG_WARN([cross compiling: use --with-maildir=/path/to/mail])
		]
	    )
	fi
    ]
) # maildir

# Where to place smtpd.sock
sockdir=/var/run
# make sure the directory exists
if test ! -d $sockdir; then
	sockdir=`eval echo ${sysconfdir}`
	case $sockdir in
		NONE/*) sockdir=`echo $sockdir | sed "s~NONE~$ac_default_prefix~"` ;;
	esac
fi

AC_ARG_WITH([path-socket],
	[  --with-path-socket=PATH	Specify path to smtpd.sock directory (default=/var/run)],
	[
		if test -n "$withval" -a "$withval" != "no" -a "${withval}" != "yes"; then
			sockdir=$withval
			if test ! -d $sockdir; then
			AC_MSG_WARN([** no $sockdir directory on this system **])
			fi
		fi
	]
)

AC_DEFINE_UNQUOTED([SMTPD_SOCKDIR], ["$sockdir"],
	[Specify location of smtpd.sock])
AC_SUBST([sockdir])
#l4470

# Where to place smtpd.pid
piddir=/var/run
AC_MSG_CHECKING([system pid directory])
AC_RUN_IFELSE(
	[
	    AC_LANG_PROGRAM([[
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_PATHS_H
#include <paths.h>
#endif
#define DATA "conftest.piddir"
		]],
		[[
#ifdef _PATH_VARRUN
FILE *fd;
int rc;

if ((fd = fopen(DATA,"w")) == NULL) { exit(1); }
if ((rc = fprintf(fd ,"%s\n", _PATH_VARRUN)) < 0) { exit(2); }
exit(0);
#else
exit(-1);
#endif
		]])
	],		[
		piddir=`cat conftest.piddir`
		AC_MSG_RESULT([$piddir from paths.h])
	],
	[
		AC_MSG_RESULT([$piddir from default value])
	],
	[
		AC_MSG_RESULT([$piddir from default value])
	]
)

AC_ARG_WITH([path-pidfile],
	[  --with-path-pidfile=PATH	Specify path to smtpd.pid directory (default=/var/run)],
	[
		if test -n "$withval" -a "$withval" != "no" -a "${withval}" != "yes"; then
			piddir=$withval
		fi
	]
)

AC_DEFINE_UNQUOTED([SMTPD_PIDDIR], ["$piddir"], [Specify location of smtpd.pid])
AC_SUBST([piddir])

AC_ARG_WITH([path-CAfile],
	[  --with-path-CAfile=FILE	Specify path to CA certificate],
)
AS_IF([test -n "$with_path_CAfile" -a "$with_path_CAfile" != no -a \
    "$with_path_CAfile" != yes], [
	AC_DEFINE_UNQUOTED([OPENSMTPD_CA_FILE], ["$with_path_CAfile"],
	    [Custom path to a CA file])
])

dnl make sure we're using the real structure members and not defines
AC_CACHE_CHECK([for msg_accrights field in struct msghdr],
		ac_cv_have_accrights_in_msghdr, [
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <stdlib.h>
		]], [[
#ifdef msg_accrights
#error "msg_accrights is a macro"
exit(1);
#endif
struct msghdr m;
m.msg_accrights = 0;
exit(0);
		]])],
		[ ac_cv_have_accrights_in_msghdr="yes" ],
		[ ac_cv_have_accrights_in_msghdr="no" ]
	)
])
if test "x$ac_cv_have_accrights_in_msghdr" = "xyes"; then
	AC_DEFINE([HAVE_ACCRIGHTS_IN_MSGHDR], [1],
		[Define if your system uses access rights style
		file descriptor passing])
fi


AC_CACHE_CHECK([for msg_control field in struct msghdr],
		ac_cv_have_control_in_msghdr, [
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <stdlib.h>
		]], [[
#ifdef msg_control
#error "msg_control is a macro"
exit(1);
#endif
struct msghdr m;
m.msg_control = 0;
exit(0);
		]])],
		[ ac_cv_have_control_in_msghdr="yes" ],
		[ ac_cv_have_control_in_msghdr="no" ]
	)
])
if test "x$ac_cv_have_control_in_msghdr" = "xyes"; then
	AC_DEFINE([HAVE_CONTROL_IN_MSGHDR], [1],
		[Define if your system uses ancillary data style
		file descriptor passing])
fi

AC_CACHE_CHECK([if libc defines __progname], ac_cv_libc_defines___progname, [
	AC_LINK_IFELSE([AC_LANG_PROGRAM([[ #include <stdio.h> ]],
		[[ extern char *__progname; printf("%s", __progname); ]])],
	[ ac_cv_libc_defines___progname="yes" ],
	[ ac_cv_libc_defines___progname="no"
	])
])
if test "x$ac_cv_libc_defines___progname" = "xyes"; then
	AC_DEFINE([HAVE___PROGNAME], [1], [Define if libc defines __progname])
fi

AC_CACHE_CHECK([whether $CC implements __FUNCTION__], ac_cv_cc_implements___FUNCTION__, [
	AC_LINK_IFELSE([AC_LANG_PROGRAM([[ #include <stdio.h> ]],
		[[ printf("%s", __FUNCTION__); ]])],
	[ ac_cv_cc_implements___FUNCTION__="yes" ],
	[ ac_cv_cc_implements___FUNCTION__="no"
	])
])
if test "x$ac_cv_cc_implements___FUNCTION__" = "xyes"; then
	AC_DEFINE([HAVE___FUNCTION__], [1],
		[Define if compiler implements __FUNCTION__])
fi

AC_CACHE_CHECK([whether $CC implements __func__], ac_cv_cc_implements___func__, [
	AC_LINK_IFELSE([AC_LANG_PROGRAM([[ #include <stdio.h> ]],
		[[ printf("%s", __func__); ]])],
	[ ac_cv_cc_implements___func__="yes" ],
	[ ac_cv_cc_implements___func__="no"
	])
])
if test "x$ac_cv_cc_implements___func__" = "xyes"; then
	AC_DEFINE([HAVE___func__], [1], [Define if compiler implements __func__])
fi

AC_CACHE_CHECK([whether va_copy exists], ac_cv_have_va_copy, [
	AC_LINK_IFELSE([AC_LANG_PROGRAM([[
#include <stdarg.h>
va_list x,y;
		]], [[ va_copy(x,y); ]])],
	[ ac_cv_have_va_copy="yes" ],
	[ ac_cv_have_va_copy="no"
	])
])
if test "x$ac_cv_have_va_copy" = "xyes"; then
	AC_DEFINE([HAVE_VA_COPY], [1], [Define if va_copy exists])
fi

AC_CACHE_CHECK([whether __va_copy exists], ac_cv_have___va_copy, [
	AC_LINK_IFELSE([AC_LANG_PROGRAM([[
#include <stdarg.h>
va_list x,y;
		]], [[ __va_copy(x,y); ]])],
	[ ac_cv_have___va_copy="yes" ], [ ac_cv_have___va_copy="no"
	])
])
if test "x$ac_cv_have___va_copy" = "xyes"; then
	AC_DEFINE([HAVE___VA_COPY], [1], [Define if __va_copy exists])
fi

AC_CACHE_CHECK([whether getopt has optreset support],
		ac_cv_have_getopt_optreset, [
	AC_LINK_IFELSE([AC_LANG_PROGRAM([[ #include <getopt.h> ]],
		[[ extern int optreset; optreset = 0; ]])],
	[ ac_cv_have_getopt_optreset="yes" ],
	[ ac_cv_have_getopt_optreset="no"
	])
])
if test "x$ac_cv_have_getopt_optreset" = "xyes"; then
	AC_DEFINE([HAVE_GETOPT_OPTRESET], [1],
		[Define if your getopt(3) defines and uses optreset])
fi

AC_CHECK_DECL([suboptarg], [
	AC_DEFINE([HAVE_SUBOPTARG], 1, [1 if have suboptarg])
], [
	AC_LIBOBJ([getsubopt])
])

# Search for fts
AC_ARG_WITH([libfts],
	[  --with-libfts=PATH		Specify path to libfts installation (default: none, part of libc)],
	[ if test "x$withval" = "xno"; then
		AC_MSG_ERROR([*** fts is required ***])
	  elif test "x$withval" != "xyes"; then
		if test -d "$withval/lib"; then
			if test -n "${need_dash_r}"; then
				LDFLAGS="-L${withval}/lib -R${withval}/lib ${LDFLAGS}"
			else
				LDFLAGS="-L${withval}/lib ${LDFLAGS}"
			fi
		else
			if test -n "${need_dash_r}"; then
				LDFLAGS="-L${withval} -R${withval} ${LDFLAGS}"
			else
				LDFLAGS="-L${withval} ${LDFLAGS}"
			fi
		fi
		if test -d "$withval/include"; then
			CPPFLAGS="-I${withval}/include ${CPPFLAGS}"
		else
			CPPFLAGS="-I${withval} ${CPPFLAGS}"
		fi
	LIBS="$LIBS -lfts"
	fi
	]
)

# Search for libevent
saved_CPPFLAGS="$CPPFLAGS"
saved_LDFLAGS="$LDFLAGS"
AC_ARG_WITH([libevent],
	[  --with-libevent=PATH          Specify path to libevent installation ],
	[
		if test "x$withval" != "xno"; then
			case "$withval" in
				# Relative paths
				./*|../*)	withval="`pwd`/$withval"
			esac
			if test -d "$withval/lib"; then
				if test -n "${need_dash_r}"; then
					LDFLAGS="-L${withval}/lib -R${withval}/lib ${LDFLAGS}"
				else
					LDFLAGS="-L${withval}/lib ${LDFLAGS}"
				fi
			elif test -d "$withval/lib64"; then
				if test -n "${need_dash_r}"; then
					LDFLAGS="-L${withval}/lib64 -R${withval}/lib64 ${LDFLAGS}"
				else
					LDFLAGS="-L${withval}/lib64 ${LDFLAGS}"
				fi
			else
				if test -n "${need_dash_r}"; then
					LDFLAGS="-L${withval} -R${withval} ${LDFLAGS}"
				else
					LDFLAGS="-L${withval} ${LDFLAGS}"
				fi
			fi
			if test -d "$withval/include"; then
				CPPFLAGS="-I${withval}/include ${CPPFLAGS}"
			else
				CPPFLAGS="-I${withval} ${CPPFLAGS}"
			fi
		fi
	]
)

AC_CHECK_HEADER([event.h], ,[AC_MSG_ERROR([*** event.h missing - please install libevent ***])],
[#include <sys/types.h>])
LIBS="$LIBS -levent"
AC_MSG_CHECKING([if programs using libevent functions will link])
AC_LINK_IFELSE(
	[AC_LANG_PROGRAM([[
	#include <event.h>
	]], [[
	event_base_new();
	]])],
	[
		AC_MSG_RESULT([yes])
	],
	[
		AC_MSG_RESULT([no])
	]
)

# Search for OpenSSL
saved_CPPFLAGS="$CPPFLAGS"
saved_LDFLAGS="$LDFLAGS"
AC_ARG_WITH([libssl],
	[  --with-libssl=PATH		Specify path to libssl installation ],
	[
		if test "x$withval" != "xno"; then
			case "$withval" in
				# Relative paths
				./*|../*)	withval="`pwd`/$withval"
			esac
			if test -d "$withval/lib"; then
				if test -n "${need_dash_r}"; then
					LDFLAGS="-L${withval}/lib -R${withval}/lib ${LDFLAGS}"
				else
					LDFLAGS="-L${withval}/lib ${LDFLAGS}"
				fi
			elif test -d "$withval/lib64"; then
				if test -n "${need_dash_r}"; then
					LDFLAGS="-L${withval}/lib64 -R${withval}/lib64 ${LDFLAGS}"
				else
					LDFLAGS="-L${withval}/lib64 ${LDFLAGS}"
				fi
			else
				if test -n "${need_dash_r}"; then
					LDFLAGS="-L${withval} -R${withval} ${LDFLAGS}"
				else
					LDFLAGS="-L${withval} ${LDFLAGS}"
				fi
			fi
			if test -d "$withval/include"; then
				CPPFLAGS="-I${withval}/include ${CPPFLAGS}"
			else
				CPPFLAGS="-I${withval} ${CPPFLAGS}"
			fi
		fi
	]
)

AC_SEARCH_LIBS([RAND_add], [crypto], [:], [
	AC_MSG_ERROR([can't find libcrypto])
])

AC_SEARCH_LIBS([SSL_CTX_new], [ssl], [:], [
	AC_MSG_ERROR([can't find libssl])
])

# Check arc4random only after libcrypto to avoid issues with old
# (pre 3.8) versions of LibreSSL.
AC_REPLACE_FUNCS([arc4random])

AC_CHECK_FUNCS([ \
	SSL_CTX_use_certificate_chain_mem \
	SSL_CTX_load_verify_mem \
	X509_LOOKUP_mem \
	OPENSSL_posix_to_tm \
	OPENSSL_gmtime \
])

AS_IF([test "x$ac_cv_func_OPENSSL_posix_to_tm" = xno], [
	AM_CFLAGS="${AM_CFLAGS} -I\${top_srcdir}/openbsd-compat/openssl/"
])

# Sanity check OpenSSL headers
AC_MSG_CHECKING([whether LibreSSL's headers match the library])
AC_RUN_IFELSE(
	[AC_LANG_PROGRAM([[
#include <stdlib.h>
#include <string.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
	]], [[
	exit(SSLeay() == OPENSSL_VERSION_NUMBER ? 0 : 1);
	]])],
	[
		AC_MSG_RESULT([yes])
	],
	[
		AC_MSG_RESULT([no])
		AC_MSG_ERROR([Your LibreSSL headers do not match your library.])
	],
	[
		AC_MSG_WARN([cross compiling: not checking])
	]
)

AC_CHECK_DECL([LIBRESSL_VERSION_NUMBER], , , [#include <openssl/ssl.h>])

dnl zlib is required
AC_ARG_WITH([libz],
	[  --with-libz=PATH		Specify path to libz installation],
	[ if test "x$withval" = "xno"; then
		AC_MSG_ERROR([*** zlib is required ***])
	  elif test "x$withval" != "xyes"; then
		if test -d "$withval/lib"; then
			if test -n "${need_dash_r}"; then
				LDFLAGS="-L${withval}/lib -R${withval}/lib ${LDFLAGS}"
			else
				LDFLAGS="-L${withval}/lib ${LDFLAGS}"
			fi
		else
			if test -n "${need_dash_r}"; then
				LDFLAGS="-L${withval} -R${withval} ${LDFLAGS}"
			else
				LDFLAGS="-L${withval} ${LDFLAGS}"
			fi
		fi
		if test -d "$withval/include"; then
			CPPFLAGS="-I${withval}/include ${CPPFLAGS}"
		else
			CPPFLAGS="-I${withval} ${CPPFLAGS}"
		fi
	fi ]
)

AC_CHECK_HEADER([zlib.h], ,[AC_MSG_ERROR([*** zlib.h missing - please install first or check config.log ***])])
AC_SEARCH_LIBS([deflate], [z], [:], [
	AC_MSG_ERROR([can't find zlib])
])

AC_ARG_WITH([table-db],
	[  --with-table-db		Enable building of table-db backend (default=no)],
	[
		if test "x$withval" = "xyes"; then
			use_db_api=1
		else
			use_db_api=0
		fi
	]
)

if test "x$use_db_api" = "x1"; then
# Search for libdb
AC_CHECK_HEADER(db_185.h, [AC_DEFINE([HAVE_DB_185_H], [], [if you have the <db_185.h> header file]) ] , [
AC_CHECK_HEADER(db.h,     [AC_DEFINE([HAVE_DB_H],     [], [if you have the <db.h> header file])     ] , [
AC_CHECK_HEADER(db1/db.h, [AC_DEFINE([HAVE_DB1_DB_H], [], [if you have the <db1/db.h> header file]) ] , [
				AC_MSG_ERROR([*** Can't find Berkeley DB headers (see config.log for details) ***])
])])])
fi

save_LIBS="$LIBS"

if test "x$use_db_api" = "x1"; then
DB_LIB=

for libdb in db db1 c; do
    AC_CHECK_LIB($libdb, dbopen,       [ DB_LIB="$libdb"; break; ],
    AC_CHECK_LIB($libdb, __db185_open, [ DB_LIB="$libdb"; break; ]))
done

if test -z "$DB_LIB"; then
    AC_MSG_ERROR([Berkeley DB not found or not built with --enable-185])
fi

DB_LIB="-l$DB_LIB"
AC_SUBST([DB_LIB])
fi

LIBS="$save_LIBS"

AM_CONDITIONAL([HAVE_DB_API], [test "x$use_db_api" = "x1"])
AM_COND_IF([HAVE_DB_API], [AC_DEFINE([HAVE_DB_API], [1], [Define to 1 if HAVE_DB_API])])

LIBS="$LIBS ${SMTPDLIBS}"

dnl Adding -Werror to CFLAGS early prevents configure tests from running.
dnl Add now.
AM_CFLAGS="$AM_CFLAGS $werror_flags"

AC_SUBST([AM_CFLAGS])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
	Makefile
	mk/Makefile
	mk/mail/Makefile
	mk/mail/mail.lmtp/Makefile
	mk/mail/mail.maildir/Makefile
	mk/mail/mail.mboxfile/Makefile
	mk/mail/mail.mda/Makefile
	mk/smtpd/Makefile
	mk/smtpctl/Makefile
	mk/smtp/Makefile
	contrib/Makefile
	contrib/libexec/Makefile
	contrib/libexec/mail.local/Makefile
	contrib/libexec/lockspool/Makefile
	contrib/libexec/encrypt/Makefile
	openbsd-compat/Makefile
])

AC_OUTPUT
