# $Id: configure.ac,v 1.519 2013/03/22 01:49:15 dtucker Exp $
#
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


#
# WE NEED TO CLEANUP CONFIGURE.AC AND MAKE IT FOLLOW THE
# STANDARD LAYOUT ...
#
# 3.1.3 Standard configure.ac Layout
#
# https://www.gnu.org/software/autoconf/manual/autoconf-2.69/html_node/Autoconf-Input-Layout.html
#


#
# AUTOCONF REQUIREMENTS
#
AC_PREREQ(2.69)


#
# AC_INIT
#
AC_INIT([OpenSMTPD],
	[portable],
	[bugs@opensmtpd.org],
	[opensmtpd],
	[https://www.OpenSMTPD.org])

AM_INIT_AUTOMAKE([subdir-objects no-dependencies])
LT_INIT

# here we should test for variables set by libtool detection
if test "x$with_pic" != "xno"; then
	CFLAGS="$CFLAGS ${pic_flag}"
fi


#
# PACKAGE INFORMATION
#
AC_LANG([C])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADER([config.h])
AC_PROG_CC
AC_CANONICAL_HOST
AC_C_BIGENDIAN


#
# CHECKS FOR PROGRAMS
#
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LIBTOOL
AC_PATH_PROG([AR], [ar])
AC_PATH_PROG([CAT], [cat])
AC_PATH_PROG([CHMOD], [chmod])
AC_PATH_PROG([CHOWN], [chown])
AC_PATH_PROG([ZCAT], [zcat])
AC_PATH_PROG([SED], [sed])
AC_PATH_PROG([TEST_MINUS_S_SH], [bash])
AC_PATH_PROG([TEST_MINUS_S_SH], [ksh])
AC_PATH_PROG([TEST_MINUS_S_SH], [sh])
AC_PATH_PROG([SH], [sh])
AC_PATH_PROG([GROFF], [groff])
AC_PATH_PROG([NROFF], [nroff])
AC_PATH_PROG([MANDOC], [mandoc])
AC_PROG_YACC

AC_SUBST([ZCAT])


if test -z "$AR"; then
	AC_MSG_ERROR([*** 'ar' missing, please install or fix your \$PATH ***])
fi

if test -z "$LD"; then
	LD=$CC
fi
AC_SUBST([LD])

dnl select manpage formatter
if test -n "$MANDOC"; then
	MANFMT="$MANDOC"
elif test -n "$NROFF"; then
	MANFMT="$NROFF -mandoc"
elif test -n "$GROFF"; then
	MANFMT="$GROFF -mandoc -Tascii"
else
	AC_MSG_WARN([no manpage formatted found])
	MANFMT="false"
fi
AC_SUBST([MANFMT])


#
# CHECKS FOR LIBRARIES
#


#
# CHECKS FOR HEADERS
#
AC_CHECK_HEADERS([ \
	arpa/nameser_compat.h \
	crypt.h \
	dirent.h \
	err.h \
	fcntl.h \
	getopt.h \
	grp.h \
	libgen.h \
	limits.h \
	maillock.h \
	mach/mach_time.h \
	ndir.h \
	netdb.h \
	pam/pam_appl.h \
	paths.h \
	security/pam_appl.h \
	shadow.h \
	sys/cdefs.h \
	sys/dir.h \
	sys/file.h \
	sys/mount.h \
	sys/ndir.h \
	sys/pstat.h \
	sys/statfs.h \
	sys/time.h \
	sys/un.h \
	time.h \
	ucred.h \
	util.h \
	utime.h \
	vis.h
])

AM_CONDITIONAL([SUPPORT_ERR_H], [test x$HAVE_ERR_H = x1])
AM_CONDITIONAL([SUPPORT_PATHS_H], [test x$HAVE_PATHS_H = x1])

# NetBSD requires sys/types.h before login_cap.h
AC_CHECK_HEADERS([login_cap.h], [], [], [
#include <sys/types.h>
])

# older BSDs need sys/param.h before sys/mount.h
AC_CHECK_HEADERS([sys/mount.h], [], [], [
#include <sys/param.h>
])

AC_CHECK_HEADERS([bsd/libutil.h libutil.h])

AC_CHECK_HEADER([fts.h],
	[],
	[AC_MSG_ERROR([*** fts.h missing - please install fts library ***])],
	[
#include <sys/types.h>
#include <sys/stat.h>
])




#
# CHECKS FOR TYPES
#
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


#
# CHECKS FOR STRUCTURES
#
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

#
# CHECKS FOR DECLARATIONS
#
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

AC_CHECK_DECLS([WAIT_MYPGRP], [], [], [
#include <sys/wait.h>
])

AC_CHECK_DECLS([writev], [], [], [
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
])

AC_CHECK_DECLS([LOG_PERROR], [], [], [
#include <syslog.h>
])


#
# CHECKS FOR COMPILER CHARACTERISTICS
#
AC_C_INLINE


AC_ARG_WITH([libs],
	[  --with-libs			Specify additional libraries to link with],
	[
		if test -n "$withval" -a "$withval" != "no" -a "${withval}" != "yes"; then
			LIBS="$LIBS $withval"
		fi
	]
)
#
# CHECKS FOR LIBRARY FUNCTIONS
#
BASENAME_SUPPORT=no
AC_SEARCH_LIBS([basename],
	[gen],
	[
		AC_DEFINE([HAVE_BASENAME], [1], 
			[Define if you have the basename() function.])
		BASENAME_SUPPORT=yes
	])
AM_CONDITIONAL([SUPPORT_BASENAME], [test $BASENAME_SUPPORT = yes])


CLOSEFROM_SUPPORT=no
AC_SEARCH_LIBS([closefrom],
	[gen],
	[
		AC_DEFINE([HAVE_CLOSEFROM], [1], 
			[Define if you have the closefrom() function.])
		CLOSEFROM_SUPPORT=yes
        AC_COMPILE_IFELSE(
            [
                AC_LANG_PROGRAM([AC_INCLUDES_DEFAULT], [[int res = closefrom(0);]])
            ],
            AC_DEFINE(HAVE_CLOSEFROM_INT, 1, [closefrom return int])
        )
	])
AM_CONDITIONAL([SUPPORT_CLOSEFROM], [test $CLOSEFROM_SUPPORT = yes])

UTIMES_SUPPORT=no
AC_SEARCH_LIBS([utimes],
	[c89],
	[
		AC_DEFINE([HAVE_UTIMES],
			[1], [Define if you have the utimes() function.])
		UTIMES_SUPPORT=yes
	])
AM_CONDITIONAL([SUPPORT_UTIMES], [test $UTIMES_SUPPORT = yes])

FMT_SCALED_SUPPORT=no
AC_SEARCH_LIBS([fmt_scaled],
	[util bsd],
	[
		AC_DEFINE([HAVE_FMT_SCALED], [1],
			[Define if you have the fmt_scaled() function.])
		FMT_SCALED_SUPPORT=yes
	])
AM_CONDITIONAL([SUPPORT_FMT_SCALED], [test $FMT_SCALED_SUPPORT = yes])

DIRNAME_SUPPORT=no
AC_SEARCH_LIBS([dirname],
	[gen],
	[
		AC_DEFINE([HAVE_DIRNAME], [1],
			[Define if you have the dirname() function.])
		DIRNAME_SUPPORT=yes
	])
AM_CONDITIONAL([SUPPORT_DIRNAME], [test $DIRNAME_SUPPORT = yes])

ERRC_SUPPORT=no
AC_CHECK_FUNC([errc],
	[
		AC_DEFINE([HAVE_ERRC], [1],
			[Define if you have the errc() function.])
		ERRC_SUPPORT=yes
	])
AM_CONDITIONAL([SUPPORT_ERRC], [test $ERRC_SUPPORT = yes])

INET_NET_PTON_SUPPORT=no
AC_SEARCH_LIBS([inet_net_pton],
	[resolv],
	[
		AC_DEFINE([HAVE_INET_NET_PTON], [1],
			[Define if you have the inet_net_pton() function.])
		INET_NET_PTON_SUPPORT=yes
	])
AM_CONDITIONAL([SUPPORT_INET_NET_PTON], [test $INET_NET_PTON_SUPPORT = yes])

CLOCK_GETTIME_SUPPORT=no
AC_SEARCH_LIBS([clock_gettime],
	[rt],
	[
		AC_DEFINE([HAVE_CLOCK_GETTIME], [1],
			[Define if you have the clock_gettime() function.])
		CLOCK_GETTIME_SUPPORT=yes
	])
AM_CONDITIONAL([SUPPORT_CLOCK_GETTIME], [test $CLOCK_GETTIME_SUPPORT = yes])

FTS_OPEN_SUPPORT=no
AC_SEARCH_LIBS([fts_open],
	[fts],
	[
		AC_DEFINE([HAVE_FTS_OPEN], [1],
			[Define if you have the fts_open() function.])
		FTS_OPEN_SUPPORT=yes
	])
AM_CONDITIONAL([SUPPORT_FTS_OPEN], [test $FTS_OPEN_SUPPORT = yes])

FLOCK_SUPPORT=no
AC_SEARCH_LIBS([flock],
	[],
	[
		AC_DEFINE([HAVE_FLOCK], [1],
			[Define if you have the flock() function.])
		FLOCK_SUPPORT=yes
	])
AM_CONDITIONAL([SUPPORT_FLOCK], [test $FLOCK_SUPPORT = yes])

DAEMON_SUPPORT=no
AC_SEARCH_LIBS([daemon],
	[bsd],
	[
		AC_DEFINE([HAVE_DAEMON], [1],
			[Define if you have the daemon() function.])
		DAEMON_SUPPORT=yes
	])
AM_CONDITIONAL([SUPPORT_DAEMON], [test $DAEMON_SUPPORT = yes])

FPARSELN_SUPPORT=no
AC_SEARCH_LIBS([fparseln],
	[util],
	[
		AC_DEFINE([HAVE_FPARSELN], [1],
			[Define if you have the fparseln() function.])
		FPARSELN_SUPPORT=yes
	])
AM_CONDITIONAL([SUPPORT_FPARSELN], [test $FPARSELN_SUPPORT = yes])

RES_9_B64_NTOP_SUPPORT=no
AC_SEARCH_LIBS([res_9_b64_ntop],
	[resolv],
	[
		AC_DEFINE([HAVE_RES_9_B64_NTOP], [1],
			[Define if you have the res_9_b64_ntop() function.])
		RES_9_B64_NTOP_SUPPORT=yes
	])
AM_CONDITIONAL([SUPPORT_RES_9_B64_NTOP], [test $RES_9_B64_NTOP_SUPPORT = yes])

SETSOCKOPT_SUPPORT=no
AC_SEARCH_LIBS([setsockopt],
	[socket],
	[
		AC_DEFINE([HAVE_SETSOCKOPT], [1],
			[Define if you have the setsockopt() function.])
		SETSOCKOPT_SUPPORT=yes
	])
AM_CONDITIONAL([SUPPORT_SETSOCKOPT], [test $SETSOCKOPT_SUPPORT = yes])

CRYPT_SUPPORT=no
AC_SEARCH_LIBS([crypt],
	[crypt],
	[
		AC_DEFINE([HAVE_CRYPT], [1],
			[Define if you have the crypt() function.])
		CRYPT_SUPPORT=yes
	])
AM_CONDITIONAL([SUPPORT_CRYPT], [test $CRYPT_SUPPORT = yes])

GETLINE_SUPPORT=no
AC_CHECK_FUNC([getline],
	[
		AC_DEFINE([HAVE_GETLINE], [1],
			[Define if you have the getline() function.])
		GETLINE_SUPPORT=yes
	])
AM_CONDITIONAL([SUPPORT_GETLINE], [test $GETLINE_SUPPORT = yes])

EXPLICIT_BZERO_SUPPORT=no
AC_CHECK_FUNC([explicit_bzero],
	[
		AC_DEFINE([HAVE_EXPLICIT_BZERO], [1],
			[Define if you have the explicit_bzero() function.])
		EXPLICIT_BZERO_SUPPORT=yes
	])
AM_CONDITIONAL([SUPPORT_EXPLICIT_BZERO], [test $EXPLICIT_BZERO_SUPPORT = yes])

CRYPT_CHECKPASS_SUPPORT=no
AC_CHECK_FUNC([crypt_checkpass],
	[
		AC_DEFINE([HAVE_CRYPT_CHECKPASS], [1],
			[Define if you have the crypt_checkpass() function.])
		CRYPT_CHECKPASS_SUPPORT=yes
	])
AM_CONDITIONAL([SUPPORT_CRYPT_CHECKPASS], [test $CRYPT_CHECKPASS_SUPPORT = yes])

STRNDUP_SUPPORT=no
AC_CHECK_FUNC([strndup],
	[
		AC_DEFINE([HAVE_STRNDUP], [1],
			[Define if you have the strndup() function.])
		STRNDUP_SUPPORT=yes
	])
AM_CONDITIONAL([SUPPORT_STRNDUP], [test $STRNDUP_SUPPORT = yes])

STRNLEN_SUPPORT=no
AC_CHECK_FUNC([strnlen],
	[
		AC_DEFINE([HAVE_STRNLEN], [1],
			[Define if you have the strnlen() function.])
		STRNLEN_SUPPORT=yes
	])
AM_CONDITIONAL([SUPPORT_STRNLEN], [test $STRNLEN_SUPPORT = yes])

AC_CHECK_FUNCS([ \
	asprintf \
	b64_ntop \
	__b64_ntop \
	b64_pton \
	__b64_pton \
	bcopy \
	calloc_conceal \
	chflags \
	crypt_checkpass \
	dirfd \
	endgrent \
	explicit_bzero \
	fchflags \
	fgetln \
	freeaddrinfo \
	freezero \
	getaddrinfo \
	getnameinfo \
	gettimeofday \
	getopt \
	getpeereid \
	getpeerucred \
	getspnam \
	inet_aton \
	inet_ntoa \
	inet_ntop \
	isblank \
	malloc_conceal \
	memmove \
	nsleep \
	pidfile \
	pw_dup \
	reallocarray \
	recallocarray \
	res_hnok \
	setenv \
	setlinebuf \
	setproctitle \
	setregid \
	setreuid \
	setresuid \
	setresgid \
	setsid \
	sigaction \
	snprintf \
	socketpair \
	strdup \
	strerror \
	strlcat \
	strlcpy \
	strmode \
	strnvis \
	strtonum \
	sysconf \
	tcgetpgrp \
	time \
	truncate \
	vasprintf \
	vsnprintf \
	waitpid \
])
AC_DEFINE([HAVE_PLEDGE], [0], [compat layer is not pledge ready])

AC_CHECK_DECL([strsep],
	[AC_CHECK_FUNCS([strsep])],
	[],
	[
#ifdef HAVE_STRING_H
# include <string.h>
#endif
	])



# These functions might be found in libressl
AC_CHECK_DECLS([strlcat, strlcpy],
	[],
	[],
	[])

#
# CHECKS FOR SYSTEM SERVICES
#
AC_MSG_CHECKING([for /proc/pid/fd directory])
if test -d "/proc/$$/fd"; then
	AC_DEFINE([HAVE_PROC_PID], [1], [Define if you have /proc/$pid/fd])
	AC_MSG_RESULT([yes])
else
	AC_MSG_RESULT([no])
fi


#
# AC_CONFIG_FILES
#

#
# AC_OUTPUT
#


###
### EVERYTHING BELOW MUST BE CLEANED AND MOVED ABOVE
###


AC_CHECK_DECL([LLONG_MAX], [have_llong_max=1], , [#include <limits.h>])
#l108

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
	[
		if test "x$withval" = "xno"; then
			need_dash_r=""
		fi
		if test "x$withval" = "xyes"; then
			need_dash_r=1
		fi
	]
)


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






#l432 (customized)
# Check for some target-specific stuff
ASR_LIB=-lasr

case "$host" in
*-*-darwin*)
	use_pie=auto
	AC_MSG_CHECKING([if we have working getaddrinfo])
	AC_RUN_IFELSE([AC_LANG_SOURCE([[ 
#include <stdlib.h>
#include <mach-o/dyld.h>
main() { if (NSVersionOfRunTimeLibrary("System") >= (60 << 16))
		exit(0);
	else
		exit(1);
}
			]])],
	[AC_MSG_RESULT([working])],
	[AC_MSG_RESULT([buggy])
	AC_DEFINE([BROKEN_GETADDRINFO], [1],
		[getaddrinfo is broken (if present)])
	],
	[AC_MSG_RESULT([assume it is working])])
	AC_DEFINE([SETEUID_BREAKS_SETUID], [1], [define if seteuid breaks setuid])
	AC_DEFINE([BROKEN_SETREUID], [1], [define if setreuid is broken])
	AC_DEFINE([BROKEN_SETREGID], [1], [define if setregid is broken])
	AC_DEFINE([BROKEN_GLOB], [1], [OS X glob does not do what we expect])
	AC_DEFINE([SPT_TYPE], [SPT_REUSEARGV],
		[Define to a Set Process Title type if your system is
		supported by bsd-setproctitle.c])
	AC_DEFINE([BROKEN_STRNVIS], [1],
	    [OSX strnvis argument order is swapped compared to OpenBSD])
	;;
*-*-dragonfly*)
	;;
*-*-linux* | *-gnu* | *-k*bsd*-gnu* )
	use_pie=auto
	CFLAGS="$CFLAGS -D_BSD_SOURCE -D_DEFAULT_SOURCE"
	AC_DEFINE([SPT_TYPE], [SPT_REUSEARGV])
	;;
*-*-netbsd*)
	if test "x$withval" != "xno"; then
		need_dash_r=1
	fi
	AC_DEFINE([BROKEN_STRNVIS], [1],
	    [NetBSD strnvis argument order is swapped compared to OpenBSD])
	;;
*-*-freebsd*)
	AC_DEFINE([BROKEN_GLOB], [1], [FreeBSD glob does not do what we need])
	AC_DEFINE([BROKEN_STRNVIS], [1],
	    [FreeBSD strnvis argument order is swapped compared to OpenBSD])
	;;
*-*-openbsd*)
	use_pie=auto
	AC_DEFINE([HAVE_ATTRIBUTE__SENTINEL__], [1], [OpenBSD's gcc has sentinel])
	AC_DEFINE([HAVE_ATTRIBUTE__BOUNDED__], [1], [OpenBSD's gcc has bounded])

	AC_DEFINE([BROKEN_STRNVIS], [0],
	    [FreeBSD strnvis argument order is swapped compared to OpenBSD])
	YACC='yacc'
	ASR_LIB=
	AC_DEFINE([NOOP_ASR_FREEADDRINFO], [0], [OpenBSD doesn't need ASR_FREEADDRINFO])
	;;
*-sun-solaris*)
	AC_DEFINE([HAVE_M_DATA], [1], [M_DATA is defined in sys/stream.h included by netinet/in.h])
	;;
esac
AC_SUBST([ASR_LIB])


AC_MSG_CHECKING([compiler and flags for sanity])
AC_RUN_IFELSE([AC_LANG_PROGRAM([[ 
#include <stdio.h>
#include <stdlib.h> ]], [[ exit(0); ]])],
	[	AC_MSG_RESULT([yes]) ],
	[
		AC_MSG_RESULT([no])
		AC_MSG_ERROR([*** compiler cannot create working executables, check config.log ***])
	],
	[	AC_MSG_WARN([cross compiling: not checking compiler sanity]) ]
)



#l1747




# Check for missing getpeereid (or equiv) support
NO_PEERCHECK=""
if test "x$ac_cv_func_getpeereid" != "xyes" -a "x$ac_cv_func_getpeerucred" != "xyes"; then
	AC_MSG_CHECKING([whether system supports SO_PEERCRED getsockopt])
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <sys/socket.h>]], [[int i = SO_PEERCRED;]])],
		[ AC_MSG_RESULT([yes])
		  AC_DEFINE([HAVE_SO_PEERCRED], [1], [Have PEERCRED socket option])
		], [AC_MSG_RESULT([no])
		NO_PEERCHECK=1
        ])
fi

#l4176 (customized s/ssh.1/smtpd/smtpd.8/)
# Options from here on. Some of these are preset by platform above
AC_ARG_WITH([mantype],
	[  --with-mantype=man|cat|doc	Set man page type],
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
if test -z "$MANTYPE"; then
	TestPath="/usr/bin${PATH_SEPARATOR}/usr/ucb"
	AC_PATH_PROGS([NROFF], [nroff awf], [/bin/false], [$TestPath])
	if ${NROFF} -mdoc ${srcdir}/smtpd/smtpd.8 >/dev/null 2>&1; then
		MANTYPE=doc
	elif ${NROFF} -man ${srcdir}/smtpd/smtpd.8 >/dev/null 2>&1; then
		MANTYPE=man
	else
		MANTYPE=cat
	fi
fi
AC_SUBST([MANTYPE])
if test "$MANTYPE" = "doc"; then
	mansubdir=man;
else
	mansubdir=$MANTYPE;
fi
AC_SUBST([mansubdir])
#l4207


#l4432 (customized s/pid/sock/)
# Whether to enable BSD auth support
BSD_AUTH_MSG=no
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


#l2757
# Check for PAM libs
PAM_MSG="no"
USE_PAM_SERVICE=smtpd
AC_ARG_WITH([auth-pam],
	[  --with-auth-pam=SERVICE	Enable PAM authentication support (default=smtpd)],
	[
		if test "x$withval" != "xno"; then
			if test -n "$withval" -a "x${withval}" != "xyes"; then
				USE_PAM_SERVICE=$withval
			fi

			if test "x$ac_cv_header_security_pam_appl_h" != "xyes" -a \
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

AC_CHECK_FUNCS([arc4random arc4random_buf arc4random_stir arc4random_uniform])

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
#l2816


##gilles

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
#l4022

#l4066
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
#l4146

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

CA_FILE=/etc/ssl/cert.pem
AC_ARG_WITH([path-CAfile],
	[  --with-path-CAfile=FILE	Specify path to CA certificate (default=/etc/ssl/cert.pem)],
	[
		if test -n "$withval" -a "$withval" != "no" -a "${withval}" != "yes"; then
			CA_FILE=$withval
		fi
	]
)
AC_SUBST([CA_FILE])






# compute LLONG_MIN and LLONG_MAX if we don't know them.
if test -z "$have_llong_max"; then
	AC_MSG_CHECKING([for max value of long long])
	AC_RUN_IFELSE(
		[AC_LANG_PROGRAM([[
#include <stdio.h>
#include <stdlib.h>
/* Why is this so damn hard? */
#ifdef __GNUC__
# undef __GNUC__
#endif
#define __USE_ISOC99
#include <limits.h>
#define DATA "conftest.llminmax"
#define my_abs(a) ((a) < 0 ? ((a) * -1) : (a))

/*
 * printf in libc on some platforms (eg old Tru64) does not understand %lld so
 * we do this the hard way.
 */
static int
fprint_ll(FILE *f, long long n)
{
	unsigned int i;
	int l[sizeof(long long) * 8];

	if (n < 0)
		if (fprintf(f, "-") < 0)
			return -1;
	for (i = 0; n != 0; i++) {
		l[i] = my_abs(n % 10);
		n /= 10;
	}
	do {
		if (fprintf(f, "%d", l[--i]) < 0)
			return -1;
	} while (i != 0);
	if (fprintf(f, " ") < 0)
		return -1;
	return 0;
}
		]], [[
	FILE *f;
	long long i, llmin, llmax = 0;

	if((f = fopen(DATA,"w")) == NULL)
		exit(1);

#if defined(LLONG_MIN) && defined(LLONG_MAX)
	fprintf(stderr, "Using system header for LLONG_MIN and LLONG_MAX\n");
	llmin = LLONG_MIN;
	llmax = LLONG_MAX;
#else
	fprintf(stderr, "Calculating  LLONG_MIN and LLONG_MAX\n");
	/* This will work on one's complement and two's complement */
	for (i = 1; i > llmax; i <<= 1, i++)
		llmax = i;
	llmin = llmax + 1LL;	/* wrap */
#endif

	/* Sanity check */
	if (llmin + 1 < llmin || llmin - 1 < llmin || llmax + 1 > llmax
	    || llmax - 1 > llmax || llmin == llmax || llmin == 0
	    || llmax == 0 || llmax < LONG_MAX || llmin > LONG_MIN) {
		fprintf(f, "unknown unknown\n");
		exit(2);
	}

	if (fprint_ll(f, llmin) < 0)
		exit(3);
	if (fprint_ll(f, llmax) < 0)
		exit(4);
	if (fclose(f) < 0)
		exit(5);
	exit(0);
		]])],
		[
			llong_min=`$AWK '{print $1}' conftest.llminmax`
			llong_max=`$AWK '{print $2}' conftest.llminmax`

			AC_MSG_RESULT([$llong_max])
			AC_DEFINE_UNQUOTED([LLONG_MAX], [${llong_max}LL],
			    [max value of long long calculated by configure])
			AC_MSG_CHECKING([for min value of long long])
			AC_MSG_RESULT([$llong_min])
			AC_DEFINE_UNQUOTED([LLONG_MIN], [${llong_min}LL],
			    [min value of long long calculated by configure])
		],
		[
			AC_MSG_RESULT([not found])
		],
		[
			AC_MSG_WARN([cross compiling: not checking])
		]
	)
fi





#l3561


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
#l3765




#l4045
STRIP_OPT=-s
AC_ARG_ENABLE([strip],
	[  --disable-strip	Disable calling strip(1) on install],
	[
		if test "x$enableval" = "xno"; then
			STRIP_OPT=
		fi
	]
)
AC_SUBST([STRIP_OPT])
#l4054



case "$host" in
*-*-openbsd*)
        pkglibexecdir="$libexecdir/smtpd"
        ;;
*)
        pkglibexecdir="$libexecdir/opensmtpd"
        ;;
esac
AC_SUBST([pkglibexecdir])









#l4742
dnl Adding -Werror to CFLAGS early prevents configure tests from running.
dnl Add now.
CFLAGS="$CFLAGS $werror_flags"

AC_SUBST([TEST_MALLOC_OPTIONS], [$TEST_MALLOC_OPTIONS])


AC_EXEEXT
#l4757


# Search for asr (based on zlib checks)
dnl asr is required
AC_ARG_WITH([libasr],
	[  --with-libasr=PATH		Specify path to libasr installation],
	[ if test "x$withval" = "xno"; then
		AC_MSG_ERROR([*** asr is required ***])
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

AC_CHECK_HEADER([asr.h], ,[AC_MSG_ERROR([*** asr.h missing - please install first or check config.log ***])],
[#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>])
AC_CHECK_LIB([asr], [asr_run], ,
	[
		saved_CPPFLAGS="$CPPFLAGS"
		saved_LDFLAGS="$LDFLAGS"
		save_LIBS="$LIBS"
		dnl Check default asr install dir
		if test -n "${need_dash_r}"; then
			LDFLAGS="-L/usr/local/lib -R/usr/local/lib ${saved_LDFLAGS}"
		else
			LDFLAGS="-L/usr/local/lib ${saved_LDFLAGS}"
		fi
		CPPFLAGS="-I/usr/local/include ${saved_CPPFLAGS}"
# don't add -lasr to LIBS, it's only added when needed
#		LIBS="$LIBS -lasr"
		AC_TRY_LINK_FUNC([asr_run], ,
			[
				AC_MSG_ERROR([*** libasr missing - please install first or check config.log ***])
			]
		)
	]
)


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
	LIBS="-lfts $LIBS"
	fi
	]
)



##chl (based on OpenSSL checks, see above)
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
			need_libevent_autodetect=no
		fi
	]
)

if test "x${need_libevent_autodetect}" != "xno"; then
   for path in /usr/local /usr; do
       if test -f "${path}/include/event.h"; then
       	  CPPFLAGS="-I${path}/include ${CPPFLAGS}"
	  LDFLAGS="-L${path}/lib ${LDFLAGS}"
       fi
   done
fi

LIBS="-levent $LIBS"

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


#l2174 (customized, bu adding -lssl to LIBS)
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
## XXX chl -lssl manually added
LIBS="-lcrypto -lssl $LIBS"
AC_TRY_LINK_FUNC([RAND_add], [AC_DEFINE([HAVE_OPENSSL], [1],
	[Define if your ssl headers are included
	with #include <openssl/header.h>])],
	[
		dnl Check default openssl install dir
		if test -n "${need_dash_r}"; then
			LDFLAGS="-L/usr/local/ssl/lib -R/usr/local/ssl/lib ${saved_LDFLAGS}"
		else
			LDFLAGS="-L/usr/local/ssl/lib ${saved_LDFLAGS}"
		fi
		CPPFLAGS="-I/usr/local/ssl/include ${saved_CPPFLAGS}"
		AC_CHECK_HEADER([openssl/opensslv.h], ,
		    [AC_MSG_ERROR([*** LibreSSL headers missing - please install first or check config.log ***])])
		AC_TRY_LINK_FUNC([RAND_add], [AC_DEFINE([HAVE_OPENSSL])],
			[
				AC_MSG_ERROR([*** Can't find recent LibreSSL libcrypto (see config.log for details) ***])
			]
		)
	]
)


LIBS="-lcrypto -lssl $LIBS"
AC_MSG_CHECKING([whether SSL_CTX_use_certificate_chain_mem is available])
AC_TRY_LINK_FUNC([SSL_CTX_use_certificate_chain_mem],
	[
		AC_DEFINE([HAVE_SSL_CTX_USE_CERTIFICATE_CHAIN_MEM], [1],
			[Define if SSL_CTX_use_certificate_chain_mem exists in libssl])
		AC_MSG_RESULT([yes])
	],
	[ AC_MSG_RESULT([no])]
)

LIBS="-lcrypto -lssl $LIBS"
AC_MSG_CHECKING([whether ECDSA is available])
AC_TRY_LINK_FUNC([ENGINE_get_ECDSA],
	[
		AC_DEFINE([SUPPORT_ECDSA], [1],
			[Define if ECDSA is supported])
		AC_MSG_RESULT([yes])
	],
	[ AC_MSG_RESULT([no])]
)

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

AC_MSG_CHECKING([if programs using LibreSSL functions will link])
AC_LINK_IFELSE(
	[AC_LANG_PROGRAM([[ #include <openssl/evp.h> ]],
	[[ SSLeay_add_all_algorithms(); ]])],
	[
		AC_MSG_RESULT([yes])
	],
	[
		AC_MSG_RESULT([no])
		saved_LIBS="$LIBS"
		LIBS="$LIBS -ldl"
		AC_MSG_CHECKING([if programs using LibreSSL need -ldl])
		AC_LINK_IFELSE(
			[AC_LANG_PROGRAM([[ #include <openssl/evp.h> ]],
			[[ SSLeay_add_all_algorithms(); ]])],
			[
				AC_MSG_RESULT([yes])
			],
			[
				AC_MSG_RESULT([no])
				LIBS="$saved_LIBS"
			]
		)
	]
)
#l2371


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
AC_CHECK_LIB([z], [deflate], ,
	[
		saved_CPPFLAGS="$CPPFLAGS"
		saved_LDFLAGS="$LDFLAGS"
		save_LIBS="$LIBS"
		dnl Check default zlib install dir
		if test -n "${need_dash_r}"; then
			LDFLAGS="-L/usr/local/lib -R/usr/local/lib ${saved_LDFLAGS}"
		else
			LDFLAGS="-L/usr/local/lib ${saved_LDFLAGS}"
		fi
		CPPFLAGS="-I/usr/local/include ${saved_CPPFLAGS}"
		LIBS="$LIBS -lz"
		AC_TRY_LINK_FUNC([deflate], [AC_DEFINE([HAVE_LIBZ])],
			[
				AC_MSG_ERROR([*** zlib missing - please install first or check config.log ***])
			]
		)
	]
)





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
##end of chl

AC_CONFIG_FILES([Makefile
		openbsd-compat/Makefile
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
		contrib/libexec/encrypt/Makefile
		])

#l4761
AC_OUTPUT
