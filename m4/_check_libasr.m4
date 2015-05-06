# LIBASR_LDFLAGS=
# LIBASR_CFLAGS=
# LIBASR_LIBS=
#
AC_DEFUN([WITH_LIBASR], [{
	AC_ARG_WITH([libasr],
		[--with-libasr=PATH			Use libasr located in PATH],
		[
			echo "####1"
			if test -d "$withval/lib"; then
				suffix="/lib"
			fi
			if test -n "${need_dash_r}"; then
				with_libasr_ldflags="-L${withval}${suffix} -R${withval}${suffix}"
			else
				with_libasr_ldflags="-L${withval}${suffix}"
			fi
			echo "####1" $with_libasr_ldflags
			if test -d "$withval/include"; then
				suffix="/include"
			fi
			with_libasr_cppflags="-I${withval}${suffix}"
			echo "####2" $with_libasr_cppflags
		]
	)
}])

AC_DEFUN([CHECK_LIBASR], [{
	ldflags_save=$LDFLAGS
	cppflags_save=$CPPFLAGS

	# REPLACE THESE TWO WITH AN EXPLICIT CHECK
	if test x"$with_libasr_cppflags" != x""; then
		CPPFLAGS=$with_libasr_cppflags
	fi
	if test x"$with_libasr_ldflags" != x""; then
		LDFLAGS=$with_libasr_ldflags
	fi

	AC_CHECK_HEADER(asr.h,
		[],
		[AC_MSG_ERROR([*** could not find libasr headers (see config.log for details) ***])],
		[
			#include <sys/types.h>
			#include <sys/socket.h>
			#include <netdb.h>
		])

	AC_CHECK_LIB(asr, asr_run, [check_libasr_lib=-lasr],		# found
		[AC_CHECK_LIB(c, asr_run, [check_libasr_lib=-lc],	# found
		[AC_MSG_ERROR([*** could not find libasr library (see config.log for details) ***])],
		[])],
		[])

	# OpenBSD's libasr does not have asr_freeaddrinfo(), we need to
	# detect it so it can be worked around.
	AC_CHECK_FUNC(asr_freeaddrinfo,
		[AC_DEFINE([HAVE_ASR_FREEADDRINFO], [], [if you have asr_freeaddrinfo() in libasr])],
		[])

	LDFLAGS=$ldflags_save
	CPPFLAGS=$cppflags_save
}])
