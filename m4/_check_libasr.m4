# LIBASR_LDFLAGS=
# LIBASR_CFLAGS=
# LIBASR_LIBS=
#
AC_DEFUN([WITH_LIBASR], [{
	AC_ARG_WITH([libasr],
		[  --with-libasr=PATH			Use libasr located in PATH],
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
}])

AC_DEFUN([CHECK_LIBASR], [{
	ldflags_save=$LDFLAGS
	cppflags_save=$CPPFLAGS

	if test "$with_libasr_ldflags" != ""; then
	   LDFLAGS=$with_libasr_ldflags
	fi
	if test "$with_libasr_cppflags" != ""; then
	   CPPFLAGS=$with_libasr_cppflags
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
