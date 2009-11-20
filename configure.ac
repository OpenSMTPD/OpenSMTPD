AC_INIT([OpenSMTPD-portable],[4.6.0],[Charles Longeau <chl@openbsd.org>])
AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LIBTOOL
AC_PROG_LN_S
AC_PATH_PROG(BYACC, byacc)

#from here everything comes from portable openssh configure.ac script

#l91
AC_CHECK_DECL(LLONG_MAX, have_llong_max=1, , [#include <limits.h>])

if test "$GCC" = "yes" || test "$GCC" = "egcs"; then
	CFLAGS="$CFLAGS -Wall -Wpointer-arith -Wuninitialized"
	GCC_VER=`$CC -v 2>&1 | $AWK '/gcc version /{print $3}'`
	case $GCC_VER in
		1.*) no_attrib_nonnull=1 ;;
		2.8* | 2.9*)
		     CFLAGS="$CFLAGS -Wsign-compare"
		     no_attrib_nonnull=1
		     ;;
		2.*) no_attrib_nonnull=1 ;;
		3.*) CFLAGS="$CFLAGS -Wsign-compare" ;;
		4.*) CFLAGS="$CFLAGS -Wsign-compare -Wno-pointer-sign" ;;
		*) ;;
	esac

	if test -z "$have_llong_max"; then
		# retry LLONG_MAX with -std=gnu99, needed on some Linuxes
		unset ac_cv_have_decl_LLONG_MAX
		saved_CFLAGS="$CFLAGS"
		CFLAGS="$CFLAGS -std=gnu99"
		AC_CHECK_DECL(LLONG_MAX,
		    [have_llong_max=1],
		    [CFLAGS="$saved_CFLAGS"],
		    [#include <limits.h>]
		)
	fi
fi

if test "x$no_attrib_nonnull" != "x1" ; then
	AC_DEFINE(HAVE_ATTRIBUTE__NONNULL__, 1, [Have attribute nonnull])
fi
#l124

#l174
AC_ARG_WITH(Werror,
	[  --with-Werror           Build main code with -Werror],
	[
		if test -n "$withval"  &&  test "x$withval" != "xno"; then
			werror_flags="-Werror"
			if test "x${withval}" != "xyes"; then
				werror_flags="$withval"
			fi
		fi
	]
)
#l184

AC_CHECK_HEADERS( \
		dirent.h \
		fcntl.h \
		ndir.h \
		pam/pam_appl.h \
		security/pam_appl.h \
		sys/dir.h \
		sys/file.h \
		sys/ndir.h \
		sys/pstat.h \
		sys/un.h \
		ucred.h \
		util.h \
                )

AC_CHECK_FUNCS( \
		arc4random \
		arc4random_uniform \
		chflags \
		closefrom \
		dirfd \
		dirname \
		fgetln \
		fparseln \
		getopt \
		getpeereid \
		setproctitle \
		strlcat \
		strlcpy \
		strsep \
		strtonum \
		strmode \
		sysconf \
		)

#chl

AC_CHECK_HEADER(db.h,     [AC_DEFINE([HAVE_DB_H],     [], [if you have the <db.h> header file]) LIBS="$LIBS -ldb" ] , [
AC_CHECK_HEADER(db1/db.h, [AC_DEFINE([HAVE_DB1_DB_H], [], [if you have the <db.h> header file]) LIBS="$LIBS -ldb1"] , [
AC_CHECK_HEADER(db_185.h, [AC_DEFINE([HAVE_DB_185_H], [], [if you have the <db.h> header file]) LIBS="$LIBS -ldb" ] , [
				AC_MSG_ERROR([*** Can't find Berkeley DB headers (see config.log for details) ***])
])])])


#l265
# login_cap.h requires sys/types.h on NetBSD
AC_CHECK_HEADERS(login_cap.h, [], [], [
#include <sys/types.h>
])
#l268

#l337
# Check for some target-specific stuff
case "$host" in
*-*-darwin*)
	AC_MSG_CHECKING(if we have working getaddrinfo)
	AC_TRY_RUN([#include <mach-o/dyld.h>
main() { if (NSVersionOfRunTimeLibrary("System") >= (60 << 16))
		exit(0);
	else
		exit(1);
}], [AC_MSG_RESULT(working)],
	[AC_MSG_RESULT(buggy)
	AC_DEFINE(BROKEN_GETADDRINFO, 1, [getaddrinfo is broken (if present)])],
	[AC_MSG_RESULT(assume it is working)])
	;;
*-*-dragonfly*)
	SSHDLIBS="$SSHDLIBS -lcrypt"
	;;
*-*-hpux*)
	# first we define all of the options common to all HP-UX releases
	CPPFLAGS="$CPPFLAGS -D_HPUX_SOURCE -D_XOPEN_SOURCE -D_XOPEN_SOURCE_EXTENDED=1"
	;;
*-*-linux*)
	case `uname -r` in
	1.*|2.0.*)
		AC_DEFINE(BROKEN_CMSG_TYPE, 1,
			[Define if cmsg_type is not passed correctly])
		;;
	esac
	;;
*-*-netbsd*)
	check_for_libcrypt_before=1
	;;
*-*-freebsd*)
	check_for_libcrypt_later=1
	;;
*-*-openbsd*)
	echo "You are drunk"
	;;
*-*-solaris*)
	;;
*-*-sunos4*)
	CPPFLAGS="$CPPFLAGS -DSUNOS4"
	;;
esac
#l896

#l917
dnl IRIX and Solaris 2.5.1 have dirname() in libgen
AC_CHECK_FUNCS(dirname, [AC_CHECK_HEADERS(libgen.h)] ,[
	AC_CHECK_LIB(gen, dirname,[
		AC_CACHE_CHECK([for broken dirname],
			ac_cv_have_broken_dirname, [
			save_LIBS="$LIBS"
			LIBS="$LIBS -lgen"
			AC_RUN_IFELSE(
				[AC_LANG_SOURCE([[
#include <libgen.h>
#include <string.h>

int main(int argc, char **argv) {
    char *s, buf[32];

    strncpy(buf,"/etc", 32);
    s = dirname(buf);
    if (!s || strncmp(s, "/", 32) != 0) {
	exit(1);
    } else {
	exit(0);
    }
}
				]])],
				[ ac_cv_have_broken_dirname="no" ],
				[ ac_cv_have_broken_dirname="yes" ],
				[ ac_cv_have_broken_dirname="no" ],
			)
			LIBS="$save_LIBS"
		])
		if test "x$ac_cv_have_broken_dirname" = "xno" ; then
			LIBS="$LIBS -lgen"
			AC_DEFINE(HAVE_DIRNAME)
			AC_CHECK_HEADERS(libgen.h)
		fi
	])
])
#l953

#l957
AC_SEARCH_LIBS(basename, gen, AC_DEFINE(HAVE_BASENAME, 1,
	[Define if you have the basename function.]))
#l958

#l1067
dnl    Checks for libutil functions
AC_CHECK_HEADERS(libutil.h)
AC_SEARCH_LIBS(fparseln, util bsd, [AC_DEFINE(HAVE_FPARSELN, 1,
	[Define if your libraries define fparseln()])])
AC_CHECK_FUNCS(fmt_scaled logout updwtmp logwtmp)
#l1071

#l1133
AC_MSG_CHECKING([for /proc/pid/fd directory])
if test -d "/proc/$$/fd" ; then
	AC_DEFINE(HAVE_PROC_PID, 1, [Define if you have /proc/$pid/fd])
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(no)
fi
#l1139

#l1484
AC_CHECK_FUNCS(setresuid, [
	dnl Some platorms have setresuid that isn't implemented, test for this
	AC_MSG_CHECKING(if setresuid seems to work)
	AC_RUN_IFELSE(
		[AC_LANG_SOURCE([[
#include <stdlib.h>
#include <errno.h>
int main(){errno=0; setresuid(0,0,0); if (errno==ENOSYS) exit(1); else exit(0);}
		]])],
		[AC_MSG_RESULT(yes)],
		[AC_DEFINE(BROKEN_SETRESUID, 1,
			[Define if your setresuid() is broken])
		 AC_MSG_RESULT(not implemented)],
		[AC_MSG_WARN([cross compiling: not checking setresuid])]
	)
])

AC_CHECK_FUNCS(setresgid, [
	dnl Some platorms have setresgid that isn't implemented, test for this
	AC_MSG_CHECKING(if setresgid seems to work)
	AC_RUN_IFELSE(
		[AC_LANG_SOURCE([[
#include <stdlib.h>
#include <errno.h>
int main(){errno=0; setresgid(0,0,0); if (errno==ENOSYS) exit(1); else exit(0);}
		]])],
		[AC_MSG_RESULT(yes)],
		[AC_DEFINE(BROKEN_SETRESGID, 1,
			[Define if your setresgid() is broken])
		 AC_MSG_RESULT(not implemented)],
		[AC_MSG_WARN([cross compiling: not checking setresuid])]
	)
])
#l1517

#l1542
# Check for broken snprintf
if test "x$ac_cv_func_snprintf" = "xyes" ; then
	AC_MSG_CHECKING([whether snprintf correctly terminates long strings])
	AC_RUN_IFELSE(
		[AC_LANG_SOURCE([[
#include <stdio.h>
int main(void){char b[5];snprintf(b,5,"123456789");exit(b[4]!='\0');}
		]])],
		[AC_MSG_RESULT(yes)],
		[
			AC_MSG_RESULT(no)
			AC_DEFINE(BROKEN_SNPRINTF, 1,
				[Define if your snprintf is busted])
			AC_MSG_WARN([****** Your snprintf() function is broken, complain to your vendor])
		],
		[ AC_MSG_WARN([cross compiling: Assuming working snprintf()]) ]
	)
fi

# If we don't have a working asprintf, then we strongly depend on vsnprintf
# returning the right thing on overflow: the number of characters it tried to
# create (as per SUSv3)
if test "x$ac_cv_func_asprintf" != "xyes" && \
   test "x$ac_cv_func_vsnprintf" = "xyes" ; then
	AC_MSG_CHECKING([whether vsnprintf returns correct values on overflow])
	AC_RUN_IFELSE(
		[AC_LANG_SOURCE([[
#include <sys/types.h>
#include <stdio.h>
#include <stdarg.h>

int x_snprintf(char *str,size_t count,const char *fmt,...)
{
	size_t ret; va_list ap;
	va_start(ap, fmt); ret = vsnprintf(str, count, fmt, ap); va_end(ap);
	return ret;
}
int main(void)
{
	char x[1];
	exit(x_snprintf(x, 1, "%s %d", "hello", 12345) == 11 ? 0 : 1);
} ]])],
		[AC_MSG_RESULT(yes)],
		[
			AC_MSG_RESULT(no)
			AC_DEFINE(BROKEN_SNPRINTF, 1,
				[Define if your snprintf is busted])
			AC_MSG_WARN([****** Your vsnprintf() function is broken, complain to your vendor])
		],
		[ AC_MSG_WARN([cross compiling: Assuming working vsnprintf()]) ]
	)
fi

# On systems where [v]snprintf is broken, but is declared in stdio,
# check that the fmt argument is const char * or just char *.
# This is only useful for when BROKEN_SNPRINTF
AC_MSG_CHECKING([whether snprintf can declare const char *fmt])
AC_COMPILE_IFELSE([AC_LANG_SOURCE([[#include <stdio.h>
	   int snprintf(char *a, size_t b, const char *c, ...) { return 0; }
	   int main(void) { snprintf(0, 0, 0); } 
    ]])],
   [AC_MSG_RESULT(yes)
    AC_DEFINE(SNPRINTF_CONST, [const],
              [Define as const if snprintf() can declare const char *fmt])],
   [AC_MSG_RESULT(no)
    AC_DEFINE(SNPRINTF_CONST, [/* not const */])])

# Check for missing getpeereid (or equiv) support
NO_PEERCHECK=""
if test "x$ac_cv_func_getpeereid" != "xyes" -a "x$ac_cv_func_getpeerucred" != "xyes"; then
	AC_MSG_CHECKING([whether system supports SO_PEERCRED getsockopt])
	AC_TRY_COMPILE(
		[#include <sys/types.h>
		 #include <sys/socket.h>],
		[int i = SO_PEERCRED;],
		[ AC_MSG_RESULT(yes)
		  AC_DEFINE(HAVE_SO_PEERCRED, 1, [Have PEERCRED socket option])
		],
		[AC_MSG_RESULT(no)
		NO_PEERCHECK=1]
        )
fi


dnl see whether mkstemp() requires XXXXXX
if test "x$ac_cv_func_mkdtemp" = "xyes" ; then
AC_MSG_CHECKING([for (overly) strict mkstemp])
AC_RUN_IFELSE(
	[AC_LANG_SOURCE([[
#include <stdlib.h>
main() { char template[]="conftest.mkstemp-test";
if (mkstemp(template) == -1)
	exit(1);
unlink(template); exit(0);
}
	]])],
	[
		AC_MSG_RESULT(no)
	],
	[
		AC_MSG_RESULT(yes)
		AC_DEFINE(HAVE_STRICT_MKSTEMP, 1, [Silly mkstemp()])
	],
	[
		AC_MSG_RESULT(yes)
		AC_DEFINE(HAVE_STRICT_MKSTEMP)
	]
)
fi
#l1649

#l1701
if test "x$ac_cv_func_getaddrinfo" = "xyes" && \
    test "x$check_for_hpux_broken_getaddrinfo" = "x1"; then
	AC_MSG_CHECKING(if getaddrinfo seems to work)
	AC_RUN_IFELSE(
		[AC_LANG_SOURCE([[
#include <stdio.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <netinet/in.h>

#define TEST_PORT "2222"

int
main(void)
{
	int err, sock;
	struct addrinfo *gai_ai, *ai, hints;
	char ntop[NI_MAXHOST], strport[NI_MAXSERV], *name = NULL;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	err = getaddrinfo(name, TEST_PORT, &hints, &gai_ai);
	if (err != 0) {
		fprintf(stderr, "getaddrinfo failed (%s)", gai_strerror(err));
		exit(1);
	}

	for (ai = gai_ai; ai != NULL; ai = ai->ai_next) {
		if (ai->ai_family != AF_INET6)
			continue;

		err = getnameinfo(ai->ai_addr, ai->ai_addrlen, ntop,
		    sizeof(ntop), strport, sizeof(strport),
		    NI_NUMERICHOST|NI_NUMERICSERV);

		if (err != 0) {
			if (err == EAI_SYSTEM)
				perror("getnameinfo EAI_SYSTEM");
			else
				fprintf(stderr, "getnameinfo failed: %s\n",
				    gai_strerror(err));
			exit(2);
		}

		sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (sock < 0)
			perror("socket");
		if (bind(sock, ai->ai_addr, ai->ai_addrlen) < 0) {
			if (errno == EBADF)
				exit(3);
		}
	}
	exit(0);
}
		]])],
		[
			AC_MSG_RESULT(yes)
		],
		[
			AC_MSG_RESULT(no)
			AC_DEFINE(BROKEN_GETADDRINFO)
		],
		[
			AC_MSG_RESULT(cross-compiling, assuming yes)
		]
	)
fi

if test "x$ac_cv_func_getaddrinfo" = "xyes" && \
    test "x$check_for_aix_broken_getaddrinfo" = "x1"; then
	AC_MSG_CHECKING(if getaddrinfo seems to work)
	AC_RUN_IFELSE(
		[AC_LANG_SOURCE([[
#include <stdio.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <netinet/in.h>

#define TEST_PORT "2222"

int
main(void)
{
	int err, sock;
	struct addrinfo *gai_ai, *ai, hints;
	char ntop[NI_MAXHOST], strport[NI_MAXSERV], *name = NULL;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	err = getaddrinfo(name, TEST_PORT, &hints, &gai_ai);
	if (err != 0) {
		fprintf(stderr, "getaddrinfo failed (%s)", gai_strerror(err));
		exit(1);
	}

	for (ai = gai_ai; ai != NULL; ai = ai->ai_next) {
		if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
			continue;

		err = getnameinfo(ai->ai_addr, ai->ai_addrlen, ntop,
		    sizeof(ntop), strport, sizeof(strport),
		    NI_NUMERICHOST|NI_NUMERICSERV);

		if (ai->ai_family == AF_INET && err != 0) {
			perror("getnameinfo");
			exit(2);
		}
	}
	exit(0);
}
		]])],
		[
			AC_MSG_RESULT(yes)
			AC_DEFINE(AIX_GETNAMEINFO_HACK, 1,
				[Define if you have a getaddrinfo that fails
				for the all-zeros IPv6 address])
		],
		[
			AC_MSG_RESULT(no)
			AC_DEFINE(BROKEN_GETADDRINFO)
		],
		[
			AC_MSG_RESULT(cross-compiling, assuming no)
		]
	)
fi
#l1834

#l1856
# Search for OpenSSL
saved_CPPFLAGS="$CPPFLAGS"
saved_LDFLAGS="$LDFLAGS"
AC_ARG_WITH(ssl-dir,
	[  --with-ssl-dir=PATH     Specify path to OpenSSL installation ],
	[
		if test "x$withval" != "xno" ; then
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
LIBS="-lcrypto $LIBS"
AC_TRY_LINK_FUNC(RAND_add, AC_DEFINE(HAVE_OPENSSL, 1,
	[Define if your ssl headers are included
	with #include <openssl/header.h>]),
	[
		dnl Check default openssl install dir
		if test -n "${need_dash_r}"; then
			LDFLAGS="-L/usr/local/ssl/lib -R/usr/local/ssl/lib ${saved_LDFLAGS}"
		else
			LDFLAGS="-L/usr/local/ssl/lib ${saved_LDFLAGS}"
		fi
		CPPFLAGS="-I/usr/local/ssl/include ${saved_CPPFLAGS}"
		AC_TRY_LINK_FUNC(RAND_add, AC_DEFINE(HAVE_OPENSSL),
			[
				AC_MSG_ERROR([*** Can't find recent OpenSSL libcrypto (see config.log for details) ***])
			]
		)
	]
)

# Determine OpenSSL header version
AC_MSG_CHECKING([OpenSSL header version])
AC_RUN_IFELSE(
	[AC_LANG_SOURCE([[
#include <stdio.h>
#include <string.h>
#include <openssl/opensslv.h>
#define DATA "conftest.sslincver"
int main(void) {
	FILE *fd;
	int rc;

	fd = fopen(DATA,"w");
	if(fd == NULL)
		exit(1);

	if ((rc = fprintf(fd ,"%x (%s)\n", OPENSSL_VERSION_NUMBER, OPENSSL_VERSION_TEXT)) <0)
		exit(1);

	exit(0);
}
	]])],
	[
		ssl_header_ver=`cat conftest.sslincver`
		AC_MSG_RESULT($ssl_header_ver)
	],
	[
		AC_MSG_RESULT(not found)
		AC_MSG_ERROR(OpenSSL version header not found.)
	],
	[
		AC_MSG_WARN([cross compiling: not checking])
	]
)

# Determine OpenSSL library version
AC_MSG_CHECKING([OpenSSL library version])
AC_RUN_IFELSE(
	[AC_LANG_SOURCE([[
#include <stdio.h>
#include <string.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#define DATA "conftest.ssllibver"
int main(void) {
	FILE *fd;
	int rc;

	fd = fopen(DATA,"w");
	if(fd == NULL)
		exit(1);

	if ((rc = fprintf(fd ,"%x (%s)\n", SSLeay(), SSLeay_version(SSLEAY_VERSION))) <0)
		exit(1);

	exit(0);
}
	]])],
	[
		ssl_library_ver=`cat conftest.ssllibver`
		AC_MSG_RESULT($ssl_library_ver)
	],
	[
		AC_MSG_RESULT(not found)
		AC_MSG_ERROR(OpenSSL library not found.)
	],
	[
		AC_MSG_WARN([cross compiling: not checking])
	]
)

AC_ARG_WITH(openssl-header-check,
	[  --without-openssl-header-check Disable OpenSSL version consistency check],
	[  if test "x$withval" = "xno" ; then
		openssl_check_nonfatal=1
	   fi
	]
)

# Sanity check OpenSSL headers
AC_MSG_CHECKING([whether OpenSSL's headers match the library])
AC_RUN_IFELSE(
	[AC_LANG_SOURCE([[
#include <string.h>
#include <openssl/opensslv.h>
int main(void) { exit(SSLeay() == OPENSSL_VERSION_NUMBER ? 0 : 1); }
	]])],
	[
		AC_MSG_RESULT(yes)
	],
	[
		AC_MSG_RESULT(no)
		if test "x$openssl_check_nonfatal" = "x"; then
			AC_MSG_ERROR([Your OpenSSL headers do not match your
library. Check config.log for details.
If you are sure your installation is consistent, you can disable the check
by running "./configure --without-openssl-header-check".
Also see contrib/findssl.sh for help identifying header/library mismatches.
])
		else
			AC_MSG_WARN([Your OpenSSL headers do not match your
library. Check config.log for details.
Also see contrib/findssl.sh for help identifying header/library mismatches.])
		fi
	],
	[
		AC_MSG_WARN([cross compiling: not checking])
	]
)

AC_MSG_CHECKING([if programs using OpenSSL functions will link])
AC_LINK_IFELSE(
	[AC_LANG_SOURCE([[
#include <openssl/evp.h>
int main(void) { SSLeay_add_all_algorithms(); }
	]])],
	[
		AC_MSG_RESULT(yes)
	],
	[
		AC_MSG_RESULT(no)
		saved_LIBS="$LIBS"
		LIBS="$LIBS -ldl"
		AC_MSG_CHECKING([if programs using OpenSSL need -ldl])
		AC_LINK_IFELSE(
			[AC_LANG_SOURCE([[
#include <openssl/evp.h>
int main(void) { SSLeay_add_all_algorithms(); }
			]])],
			[
				AC_MSG_RESULT(yes)
			],
			[
				AC_MSG_RESULT(no)
				LIBS="$saved_LIBS"
			]
		)
	]
)

AC_ARG_WITH(ssl-engine,
	[  --with-ssl-engine       Enable OpenSSL (hardware) ENGINE support ],
	[ if test "x$withval" != "xno" ; then
		AC_MSG_CHECKING(for OpenSSL ENGINE support)
		AC_TRY_COMPILE(
			[ #include <openssl/engine.h>],
			[
ENGINE_load_builtin_engines();ENGINE_register_all_complete();
			],
			[ AC_MSG_RESULT(yes)
			  AC_DEFINE(USE_OPENSSL_ENGINE, 1,
			     [Enable OpenSSL engine support])
			],
			[ AC_MSG_ERROR(OpenSSL ENGINE support not found)]
		)
	  fi ]
)
#l1971

#l1991
# Some systems want crypt() from libcrypt, *not* the version in OpenSSL,
# because the system crypt() is more featureful.
if test "x$check_for_libcrypt_before" = "x1"; then
	AC_CHECK_LIB(crypt, crypt)
fi

# Some Linux systems (Slackware) need crypt() from libcrypt, *not* the
# version in OpenSSL.
if test "x$check_for_libcrypt_later" = "x1"; then
	AC_CHECK_LIB(crypt, crypt, LIBS="$LIBS -lcrypt")
fi
#l2001

#l2016
### Configure cryptographic random number support

# Check wheter OpenSSL seeds itself
AC_MSG_CHECKING([whether OpenSSL's PRNG is internally seeded])
AC_RUN_IFELSE(
	[AC_LANG_SOURCE([[
#include <string.h>
#include <openssl/rand.h>
int main(void) { exit(RAND_status() == 1 ? 0 : 1); }
	]])],
	[
		OPENSSL_SEEDS_ITSELF=yes
		AC_MSG_RESULT(yes)
	],
	[
		AC_MSG_RESULT(no)
		# Default to use of the rand helper if OpenSSL doesn't
		# seed itself
		USE_RAND_HELPER=yes
	],
	[
		AC_MSG_WARN([cross compiling: assuming yes])
		# This is safe, since all recent OpenSSL versions will
		# complain at runtime if not seeded correctly.
		OPENSSL_SEEDS_ITSELF=yes
	]
)

# Check for PAM libs
PAM_MSG="no"
AC_ARG_WITH(pam,
	[  --with-pam              Enable PAM support ],
	[
		if test "x$withval" != "xno" ; then
			if test "x$ac_cv_header_security_pam_appl_h" != "xyes" && \
			   test "x$ac_cv_header_pam_pam_appl_h" != "xyes" ; then
				AC_MSG_ERROR([PAM headers not found])
			fi

			saved_LIBS="$LIBS"
			AC_CHECK_LIB(dl, dlopen, , )
			AC_CHECK_LIB(pam, pam_set_item, , AC_MSG_ERROR([*** libpam missing]))
			AC_CHECK_FUNCS(pam_getenvlist)
			AC_CHECK_FUNCS(pam_putenv)
			LIBS="$saved_LIBS"

			PAM_MSG="yes"

			SSHDLIBS="$SSHDLIBS -lpam"
			AC_DEFINE(USE_PAM, 1,
				[Define if you want to enable PAM support])

			if test $ac_cv_lib_dl_dlopen = yes; then
				case "$LIBS" in
				*-ldl*)
					# libdl already in LIBS
					;;
				*)
					SSHDLIBS="$SSHDLIBS -ldl"
					;;
				esac
			fi
		fi
	]
)

# Check for older PAM
if test "x$PAM_MSG" = "xyes" ; then
	# Check PAM strerror arguments (old PAM)
	AC_MSG_CHECKING([whether pam_strerror takes only one argument])
	AC_TRY_COMPILE(
		[
#include <stdlib.h>
#if defined(HAVE_SECURITY_PAM_APPL_H)
#include <security/pam_appl.h>
#elif defined (HAVE_PAM_PAM_APPL_H)
#include <pam/pam_appl.h>
#endif
		],
		[(void)pam_strerror((pam_handle_t *)NULL, -1);],
		[AC_MSG_RESULT(no)],
		[
			AC_DEFINE(HAVE_OLD_PAM, 1,
				[Define if you have an old version of PAM
				which takes only one argument to pam_strerror])
			AC_MSG_RESULT(yes)
			PAM_MSG="yes (old library)"
		]
	)
fi

# Do we want to force the use of the rand helper?
AC_ARG_WITH(rand-helper,
	[  --with-rand-helper      Use subprocess to gather strong randomness ],
	[
		if test "x$withval" = "xno" ; then
			# Force use of OpenSSL's internal RNG, even if
			# the previous test showed it to be unseeded.
			if test -z "$OPENSSL_SEEDS_ITSELF" ; then
				AC_MSG_WARN([*** Forcing use of OpenSSL's non-self-seeding PRNG])
				OPENSSL_SEEDS_ITSELF=yes
				USE_RAND_HELPER=""
			fi
		else
			USE_RAND_HELPER=yes
		fi
	],
)

# Which randomness source do we use?
if test ! -z "$OPENSSL_SEEDS_ITSELF" && test -z "$USE_RAND_HELPER" ; then
	# OpenSSL only
	AC_DEFINE(OPENSSL_PRNG_ONLY, 1,
		[Define if you want OpenSSL's internally seeded PRNG only])
	RAND_MSG="OpenSSL internal ONLY"
	INSTALL_SSH_RAND_HELPER=""
elif test ! -z "$USE_RAND_HELPER" ; then
	# install rand helper
	RAND_MSG="ssh-rand-helper"
	INSTALL_SSH_RAND_HELPER="yes"
fi
AC_SUBST(INSTALL_SSH_RAND_HELPER)

### Configuration of ssh-rand-helper

# PRNGD TCP socket
AC_ARG_WITH(prngd-port,
	[  --with-prngd-port=PORT  read entropy from PRNGD/EGD TCP localhost:PORT],
	[
		case "$withval" in
		no)
			withval=""
			;;
		[[0-9]]*)
			;;
		*)
			AC_MSG_ERROR(You must specify a numeric port number for --with-prngd-port)
			;;
		esac
		if test ! -z "$withval" ; then
			PRNGD_PORT="$withval"
			AC_DEFINE_UNQUOTED(PRNGD_PORT, $PRNGD_PORT,
				[Port number of PRNGD/EGD random number socket])
		fi
	]
)

# PRNGD Unix domain socket
AC_ARG_WITH(prngd-socket,
	[  --with-prngd-socket=FILE read entropy from PRNGD/EGD socket FILE (default=/var/run/egd-pool)],
	[
		case "$withval" in
		yes)
			withval="/var/run/egd-pool"
			;;
		no)
			withval=""
			;;
		/*)
			;;
		*)
			AC_MSG_ERROR(You must specify an absolute path to the entropy socket)
			;;
		esac

		if test ! -z "$withval" ; then
			if test ! -z "$PRNGD_PORT" ; then
				AC_MSG_ERROR(You may not specify both a PRNGD/EGD port and socket)
			fi
			if test ! -r "$withval" ; then
				AC_MSG_WARN(Entropy socket is not readable)
			fi
			PRNGD_SOCKET="$withval"
			AC_DEFINE_UNQUOTED(PRNGD_SOCKET, "$PRNGD_SOCKET",
				[Location of PRNGD/EGD random number socket])
		fi
	],
	[
		# Check for existing socket only if we don't have a random device already
		if test "$USE_RAND_HELPER" = yes ; then
			AC_MSG_CHECKING(for PRNGD/EGD socket)
			# Insert other locations here
			for sock in /var/run/egd-pool /dev/egd-pool /etc/entropy; do
				if test -r $sock && $TEST_MINUS_S_SH -c "test -S $sock -o -p $sock" ; then
					PRNGD_SOCKET="$sock"
					AC_DEFINE_UNQUOTED(PRNGD_SOCKET, "$PRNGD_SOCKET")
					break;
				fi
			done
			if test ! -z "$PRNGD_SOCKET" ; then
				AC_MSG_RESULT($PRNGD_SOCKET)
			else
				AC_MSG_RESULT(not found)
			fi
		fi
	]
)
#l2212

#l2312
# compute LLONG_MIN and LLONG_MAX if we don't know them.
if test -z "$have_llong_max"; then
	AC_MSG_CHECKING([for max value of long long])
	AC_RUN_IFELSE(
		[AC_LANG_SOURCE([[
#include <stdio.h>
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

int main(void) {
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
}
		]])],
		[
			llong_min=`$AWK '{print $1}' conftest.llminmax`
			llong_max=`$AWK '{print $2}' conftest.llminmax`

			AC_MSG_RESULT($llong_max)
			AC_DEFINE_UNQUOTED(LLONG_MAX, [${llong_max}LL],
			    [max value of long long calculated by configure])
			AC_MSG_CHECKING([for min value of long long])
			AC_MSG_RESULT($llong_min)
			AC_DEFINE_UNQUOTED(LLONG_MIN, [${llong_min}LL],
			    [min value of long long calculated by configure])
		],
		[
			AC_MSG_RESULT(not found)
		],
		[
			AC_MSG_WARN([cross compiling: not checking])
		]
	)
fi


# More checks for data types
AC_CACHE_CHECK([for u_int type], ac_cv_have_u_int, [
	AC_TRY_COMPILE(
		[ #include <sys/types.h> ],
		[ u_int a; a = 1;],
		[ ac_cv_have_u_int="yes" ],
		[ ac_cv_have_u_int="no" ]
	)
])
if test "x$ac_cv_have_u_int" = "xyes" ; then
	AC_DEFINE(HAVE_U_INT, 1, [define if you have u_int data type])
	have_u_int=1
fi

AC_CACHE_CHECK([for intXX_t types], ac_cv_have_intxx_t, [
	AC_TRY_COMPILE(
		[ #include <sys/types.h> ],
		[ int8_t a; int16_t b; int32_t c; a = b = c = 1;],
		[ ac_cv_have_intxx_t="yes" ],
		[ ac_cv_have_intxx_t="no" ]
	)
])
if test "x$ac_cv_have_intxx_t" = "xyes" ; then
	AC_DEFINE(HAVE_INTXX_T, 1, [define if you have intxx_t data type])
	have_intxx_t=1
fi

if (test -z "$have_intxx_t" && \
	   test "x$ac_cv_header_stdint_h" = "xyes")
then
    AC_MSG_CHECKING([for intXX_t types in stdint.h])
	AC_TRY_COMPILE(
		[ #include <stdint.h> ],
		[ int8_t a; int16_t b; int32_t c; a = b = c = 1;],
		[
			AC_DEFINE(HAVE_INTXX_T)
			AC_MSG_RESULT(yes)
		],
		[ AC_MSG_RESULT(no) ]
	)
fi

AC_CACHE_CHECK([for int64_t type], ac_cv_have_int64_t, [
	AC_TRY_COMPILE(
		[
#include <sys/types.h>
#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif
#include <sys/socket.h>
#ifdef HAVE_SYS_BITYPES_H
# include <sys/bitypes.h>
#endif
		],
		[ int64_t a; a = 1;],
		[ ac_cv_have_int64_t="yes" ],
		[ ac_cv_have_int64_t="no" ]
	)
])
if test "x$ac_cv_have_int64_t" = "xyes" ; then
	AC_DEFINE(HAVE_INT64_T, 1, [define if you have int64_t data type])
fi

AC_CACHE_CHECK([for u_intXX_t types], ac_cv_have_u_intxx_t, [
	AC_TRY_COMPILE(
		[ #include <sys/types.h> ],
		[ u_int8_t a; u_int16_t b; u_int32_t c; a = b = c = 1;],
		[ ac_cv_have_u_intxx_t="yes" ],
		[ ac_cv_have_u_intxx_t="no" ]
	)
])
if test "x$ac_cv_have_u_intxx_t" = "xyes" ; then
	AC_DEFINE(HAVE_U_INTXX_T, 1, [define if you have u_intxx_t data type])
	have_u_intxx_t=1
fi

if test -z "$have_u_intxx_t" ; then
    AC_MSG_CHECKING([for u_intXX_t types in sys/socket.h])
	AC_TRY_COMPILE(
		[ #include <sys/socket.h> ],
		[ u_int8_t a; u_int16_t b; u_int32_t c; a = b = c = 1;],
		[
			AC_DEFINE(HAVE_U_INTXX_T)
			AC_MSG_RESULT(yes)
		],
		[ AC_MSG_RESULT(no) ]
	)
fi

AC_CACHE_CHECK([for u_int64_t types], ac_cv_have_u_int64_t, [
	AC_TRY_COMPILE(
		[ #include <sys/types.h> ],
		[ u_int64_t a; a = 1;],
		[ ac_cv_have_u_int64_t="yes" ],
		[ ac_cv_have_u_int64_t="no" ]
	)
])
if test "x$ac_cv_have_u_int64_t" = "xyes" ; then
	AC_DEFINE(HAVE_U_INT64_T, 1, [define if you have u_int64_t data type])
	have_u_int64_t=1
fi

if test -z "$have_u_int64_t" ; then
    AC_MSG_CHECKING([for u_int64_t type in sys/bitypes.h])
	AC_TRY_COMPILE(
		[ #include <sys/bitypes.h> ],
		[ u_int64_t a; a = 1],
		[
			AC_DEFINE(HAVE_U_INT64_T)
			AC_MSG_RESULT(yes)
		],
		[ AC_MSG_RESULT(no) ]
	)
fi

if test -z "$have_u_intxx_t" ; then
	AC_CACHE_CHECK([for uintXX_t types], ac_cv_have_uintxx_t, [
		AC_TRY_COMPILE(
			[
#include <sys/types.h>
			],
			[ uint8_t a; uint16_t b; uint32_t c; a = b = c = 1; ],
			[ ac_cv_have_uintxx_t="yes" ],
			[ ac_cv_have_uintxx_t="no" ]
		)
	])
	if test "x$ac_cv_have_uintxx_t" = "xyes" ; then
		AC_DEFINE(HAVE_UINTXX_T, 1,
			[define if you have uintxx_t data type])
	fi
fi

if test -z "$have_uintxx_t" ; then
    AC_MSG_CHECKING([for uintXX_t types in stdint.h])
	AC_TRY_COMPILE(
		[ #include <stdint.h> ],
		[ uint8_t a; uint16_t b; uint32_t c; a = b = c = 1;],
		[
			AC_DEFINE(HAVE_UINTXX_T)
			AC_MSG_RESULT(yes)
		],
		[ AC_MSG_RESULT(no) ]
	)
fi

if (test -z "$have_u_intxx_t" || test -z "$have_intxx_t" && \
	   test "x$ac_cv_header_sys_bitypes_h" = "xyes")
then
	AC_MSG_CHECKING([for intXX_t and u_intXX_t types in sys/bitypes.h])
	AC_TRY_COMPILE(
		[
#include <sys/bitypes.h>
		],
		[
			int8_t a; int16_t b; int32_t c;
			u_int8_t e; u_int16_t f; u_int32_t g;
			a = b = c = e = f = g = 1;
		],
		[
			AC_DEFINE(HAVE_U_INTXX_T)
			AC_DEFINE(HAVE_INTXX_T)
			AC_MSG_RESULT(yes)
		],
		[AC_MSG_RESULT(no)]
	)
fi


AC_CACHE_CHECK([for u_char], ac_cv_have_u_char, [
	AC_TRY_COMPILE(
		[
#include <sys/types.h>
		],
		[ u_char foo; foo = 125; ],
		[ ac_cv_have_u_char="yes" ],
		[ ac_cv_have_u_char="no" ]
	)
])
if test "x$ac_cv_have_u_char" = "xyes" ; then
	AC_DEFINE(HAVE_U_CHAR, 1, [define if you have u_char data type])
fi
#l2591


#l2601
AC_CACHE_CHECK([for size_t], ac_cv_have_size_t, [
	AC_TRY_COMPILE(
		[
#include <sys/types.h>
		],
		[ size_t foo; foo = 1235; ],
		[ ac_cv_have_size_t="yes" ],
		[ ac_cv_have_size_t="no" ]
	)
])
if test "x$ac_cv_have_size_t" = "xyes" ; then
	AC_DEFINE(HAVE_SIZE_T, 1, [define if you have size_t data type])
fi

AC_CACHE_CHECK([for ssize_t], ac_cv_have_ssize_t, [
	AC_TRY_COMPILE(
		[
#include <sys/types.h>
		],
		[ ssize_t foo; foo = 1235; ],
		[ ac_cv_have_ssize_t="yes" ],
		[ ac_cv_have_ssize_t="no" ]
	)
])
if test "x$ac_cv_have_ssize_t" = "xyes" ; then
	AC_DEFINE(HAVE_SSIZE_T, 1, [define if you have ssize_t data type])
fi
#l2627

#l2643
AC_CACHE_CHECK([for sa_family_t], ac_cv_have_sa_family_t, [
	AC_TRY_COMPILE(
		[
#include <sys/types.h>
#include <sys/socket.h>
		],
		[ sa_family_t foo; foo = 1235; ],
		[ ac_cv_have_sa_family_t="yes" ],
		[ AC_TRY_COMPILE(
		  [
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
		],
		[ sa_family_t foo; foo = 1235; ],
		[ ac_cv_have_sa_family_t="yes" ],

		[ ac_cv_have_sa_family_t="no" ]
	)]
	)
])
if test "x$ac_cv_have_sa_family_t" = "xyes" ; then
	AC_DEFINE(HAVE_SA_FAMILY_T, 1,
		[define if you have sa_family_t data type])
fi
#l2667

#l2683
AC_CACHE_CHECK([for mode_t], ac_cv_have_mode_t, [
	AC_TRY_COMPILE(
		[
#include <sys/types.h>
		],
		[ mode_t foo; foo = 1235; ],
		[ ac_cv_have_mode_t="yes" ],
		[ ac_cv_have_mode_t="no" ]
	)
])
if test "x$ac_cv_have_mode_t" = "xyes" ; then
	AC_DEFINE(HAVE_MODE_T, 1, [define if you have mode_t data type])
fi
#l2695


#chl part
AC_CACHE_CHECK([for in_port_t], ac_cv_have_in_port_t, [
	AC_TRY_COMPILE(
		[
#include <sys/types.h>
		],
		[ in_port_t foo; foo = 1235; ],
		[ ac_cv_have_in_port_t="yes" ],
		[ ac_cv_have_in_port_t="no" ]
	)
])
if test "x$ac_cv_have_in_port_t" = "xyes" ; then
	AC_DEFINE(HAVE_IN_PORT_T, 1, [define if you have in_port_t data type])
fi
#chl part

# From OpenNTPD portable
AC_CHECK_MEMBER(struct sockaddr.sa_len,
	AC_DEFINE(HAVE_SOCKADDR_SA_LEN, [], [Have sockaddr.sa_len]), ,
	[ #include <netdb.h>
	  #include <netinet/in.h>
	  #include <sys/socket.h> ]
)

AC_CHECK_MEMBER(struct sockaddr.ss_len,
	AC_DEFINE(HAVE_SOCKADDR_SS_LEN, [], [Have sockaddr_storage.ss_len]), ,
	[ #include <netdb.h>
	  #include <netinet/in.h>
	  #include <sys/socket.h> ]
)



#l3049
AC_CACHE_CHECK([whether getopt has optreset support],
		ac_cv_have_getopt_optreset, [
	AC_TRY_LINK(
		[
#include <getopt.h>
		],
		[ extern int optreset; optreset = 0; ],
		[ ac_cv_have_getopt_optreset="yes" ],
		[ ac_cv_have_getopt_optreset="no" ]
	)
])
if test "x$ac_cv_have_getopt_optreset" = "xyes" ; then
	AC_DEFINE(HAVE_GETOPT_OPTRESET, 1,
		[Define if your getopt(3) defines and uses optreset])
fi
#l3063

#l3149
# Check libraries needed by DNS fingerprint support
AC_SEARCH_LIBS(getrrsetbyname, resolv,
	[AC_DEFINE(HAVE_GETRRSETBYNAME, 1,
		[Define if getrrsetbyname() exists])],
	[
		# Needed by our getrrsetbyname()
		AC_SEARCH_LIBS(res_query, resolv)
		AC_SEARCH_LIBS(dn_expand, resolv)
		AC_MSG_CHECKING(if res_query will link)
		AC_TRY_LINK_FUNC(res_query, AC_MSG_RESULT(yes),
		   [AC_MSG_RESULT(no)
		    saved_LIBS="$LIBS"
		    LIBS="$LIBS -lresolv"
		    AC_MSG_CHECKING(for res_query in -lresolv)
		    AC_LINK_IFELSE([
#include <resolv.h>
int main()
{
	res_query (0, 0, 0, 0, 0);
	return 0;
}
			],
			[LIBS="$LIBS -lresolv"
			 AC_MSG_RESULT(yes)],
			[LIBS="$saved_LIBS"
			 AC_MSG_RESULT(no)])
		    ])
		AC_CHECK_FUNCS(_getshort _getlong)
		AC_CHECK_DECLS([_getshort, _getlong], , ,
		    [#include <sys/types.h>
		    #include <arpa/nameser.h>])
		AC_CHECK_MEMBER(HEADER.ad,
			[AC_DEFINE(HAVE_HEADER_AD, 1,
			    [Define if HEADER.ad exists in arpa/nameser.h])],,
			[#include <arpa/nameser.h>])
	])
#l3184

#l3515
# Looking for programs, paths and files

PRIVSEP_PATH=/var/empty
AC_ARG_WITH(privsep-path,
	[  --with-privsep-path=xxx Path for privilege separation chroot (default=/var/empty)],
	[
		if test -n "$withval"  &&  test "x$withval" != "xno"  &&  \
		    test "x${withval}" != "xyes"; then
			PRIVSEP_PATH=$withval
		fi
	]
)
AC_SUBST(PRIVSEP_PATH)
#l3528

#l3678
# Whether to enable BSD auth support
BSD_AUTH_MSG=no
AC_ARG_WITH(bsd-auth,
	[  --with-bsd-auth         Enable BSD auth support],
	[
		if test "x$withval" != "xno" ; then
			AC_DEFINE(BSD_AUTH, 1,
				[Define if you have BSD auth support])
			BSD_AUTH_MSG=yes
		fi
	]
)
#l3689


dnl AC_DEFINE([_GNU_SOURCE], [], [Enable GNU Extensions])


#l3986
dnl Adding -Werror to CFLAGS early prevents configure tests from running.
dnl Add now.
CFLAGS="$CFLAGS $werror_flags"

AC_CONFIG_HEADER(config.h)
AC_CONFIG_FILES([Makefile
		openbsd-compat/Makefile
		src/Makefile
		])

AC_OUTPUT 

# Print summary of options

# Someone please show me a better way :)
A=`eval echo ${prefix}` ; A=`eval echo ${A}`
B=`eval echo ${bindir}` ; B=`eval echo ${B}`
C=`eval echo ${sbindir}` ; C=`eval echo ${C}`
D=`eval echo ${sysconfdir}` ; D=`eval echo ${D}`
#E=`eval echo ${libexecdir}/ssh-askpass` ; E=`eval echo ${E}`
F=`eval echo ${mandir}/${mansubdir}X` ; F=`eval echo ${F}`
#G=`eval echo ${piddir}` ; G=`eval echo ${G}`
H=`eval echo ${PRIVSEP_PATH}` ; H=`eval echo ${H}`
I=`eval echo ${user_path}` ; I=`eval echo ${I}`
J=`eval echo ${superuser_path}` ; J=`eval echo ${J}`

echo ""
echo "OpenSMTPD has been configured with the following options:"
echo "                     User binaries: $B"
echo "                   System binaries: $C"
echo "               Configuration files: $D"
#echo "                   Askpass program: $E"
echo "                      Manual pages: $F"
#echo "                          PID file: $G"
echo "  Privilege separation chroot path: $H"
if test "x$external_path_file" = "x/etc/login.conf" ; then
echo "   At runtime, sshd will use the path defined in $external_path_file"
echo "   Make sure the path to scp is present, otherwise scp will not work"
else
echo "            sshd default user PATH: $I"
	if test ! -z "$external_path_file"; then
echo "   (If PATH is set in $external_path_file it will be used instead. If"
echo "   used, ensure the path to scp is present, otherwise scp will not work.)"
	fi
fi
if test ! -z "$superuser_path" ; then
echo "          sshd superuser user PATH: $J"
fi
echo "                    Manpage format: $MANTYPE"
echo "                       PAM support: $PAM_MSG"
#echo "                   OSF SIA support: $SIA_MSG"
#echo "                 KerberosV support: $KRB5_MSG"
#echo "                   SELinux support: $SELINUX_MSG"
#echo "                 Smartcard support: $SCARD_MSG"
#echo "                     S/KEY support: $SKEY_MSG"
#echo "              TCP Wrappers support: $TCPW_MSG"
#echo "              MD5 password support: $MD5_MSG"
#echo "                   libedit support: $LIBEDIT_MSG"
#echo "  Solaris process contract support: $SPC_MSG"
#echo "       IP address in \$DISPLAY hack: $DISPLAY_HACK_MSG"
#echo "           Translate v4 in v6 hack: $IPV4_IN6_HACK_MSG"
echo "                  BSD Auth support: $BSD_AUTH_MSG"
echo "              Random number source: $RAND_MSG"
if test ! -z "$USE_RAND_HELPER" ; then
echo "     ssh-rand-helper collects from: $RAND_HELPER_MSG"
fi

echo ""

echo "              Host: ${host}"
echo "          Compiler: ${CC}"
echo "    Compiler flags: ${CFLAGS}"
echo "Preprocessor flags: ${CPPFLAGS}"
echo "      Linker flags: ${LDFLAGS}"
echo "         Libraries: ${LIBS}"
if test ! -z "${SSHDLIBS}"; then
echo "         +for sshd: ${SSHDLIBS}"
fi

echo ""

if test "x$MAKE_PACKAGE_SUPPORTED" = "xyes" ; then
	echo "SVR4 style packages are supported with \"make package\""
	echo ""
fi

if test "x$PAM_MSG" = "xyes" ; then
	echo "PAM is enabled. You may need to install a PAM control file "
	echo "for sshd, otherwise password authentication may fail. "
	echo "Example PAM control files can be found in the contrib/ "
	echo "subdirectory"
	echo ""
fi

if test ! -z "$RAND_HELPER_CMDHASH" ; then
	echo "WARNING: you are using the builtin random number collection "
	echo "service. Please read WARNING.RNG and request that your OS "
	echo "vendor includes kernel-based random number collection in "
	echo "future versions of your OS."
	echo ""
fi

if test ! -z "$NO_PEERCHECK" ; then
	echo "WARNING: the operating system that you are using does not"
	echo "appear to support getpeereid(), getpeerucred() or the"
	echo "SO_PEERCRED getsockopt() option. These facilities are used to"
	echo "enforce security checks to prevent unauthorised connections to"
	echo "ssh-agent. Their absence increases the risk that a malicious"
	echo "user can connect to your agent."
	echo ""
fi

if test "$AUDIT_MODULE" = "bsm" ; then
	echo "WARNING: BSM audit support is currently considered EXPERIMENTAL."
	echo "See the Solaris section in README.platform for details."
fi
#l4100
