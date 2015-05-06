AC_DEFUN([CHECK_SYSTEM], [{
case "$host" in
*-*-darwin*)
	AC_MSG_CHECKING([if we have working getaddrinfo])
	AC_RUN_IFELSE([AC_LANG_SOURCE([[ #include <mach-o/dyld.h>
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
	AC_DEFINE([SETEUID_BREAKS_SETUID], [1],
	    [Define if your platform breaks doing a seteuid before a setuid])
	AC_DEFINE([BROKEN_SETREUID], [1], [Define if your setreuid() is broken])
	AC_DEFINE([BROKEN_SETREGID], [1], [Define if your setregid() is broken])
	AC_DEFINE([BROKEN_GLOB], [1], [OS X glob does not do what we expect])
	AC_DEFINE([SPT_TYPE], [SPT_REUSEARGV],
		[Define to a Set Process Title type if your system is
		supported by bsd-setproctitle.c])
	;;
*-*-dragonfly*)
	LIBS_SMTPD="$LIBS_SMTPD -lcrypt"
	;;
*-*-linux* | *-gnu* | *-k*bsd*-gnu* )
	check_for_libcrypt_later=1
	AC_DEFINE([SPT_TYPE], [SPT_REUSEARGV])
	case `uname -r` in
	1.*|2.0.*)
		AC_DEFINE(BROKEN_CMSG_TYPE, 1,
			[Define if cmsg_type is not passed correctly])
		;;
	esac
	;;
*-*-netbsd*)
	check_for_libcrypt_before=1
	need_dash_r=1
	AC_DEFINE([BROKEN_STRNVIS], [1],
	    [NetBSD strnvis argument order is swapped compared to OpenBSD])
	;;
*-*-freebsd*)
	check_for_libcrypt_later=1
	AC_DEFINE([BROKEN_GLOB], [1], [FreeBSD glob does not do what we need])
	AC_DEFINE([BROKEN_STRNVIS], [1],
	    [FreeBSD strnvis argument order is swapped compared to OpenBSD])
	;;
*-*-openbsd*)
	AC_DEFINE([HAVE_ATTRIBUTE__SENTINEL__], [1], [OpenBSD's gcc has sentinel])
	AC_DEFINE([HAVE_ATTRIBUTE__BOUNDED__], [1], [OpenBSD's gcc has bounded])
	AC_DEFINE([BROKEN_STRNVIS], [1],
	    [Temporarily to fix build on OpenBSD])
	echo "Please use -current or a native version at http://www.opensmtpd.org/archives/"
	;;
esac
}])

