AC_DEFUN([WITH_LIBEVENT], [{
	AC_ARG_WITH([libevent],
		[  --with-libevent=PATH			Use libevent located in PATH],
		[
			with_libevent_include=${withval}
			if test -d "${with_libevent_include}/include"; then
				with_libevent_include="${with_libevent_include}/include"
			fi

			with_libevent_lib=${withval}
			if test -d "${with_libevent_lib}/lib"; then
				with_libevent_lib="${with_libevent_lib}/lib"
			fi

			with_libevent_cppflags="-I${with_libevent_include}"

			with_libevent_ldflags="-L${with_libevent_lib}"
			if test -n "${need_dash_r}"; then
				with_libevent_ldflags="${with_libevent_ldflags} -R${with_libevent_lib}"
			fi
		]
	)
}])

AC_DEFUN([CHECK_LIBEVENT], [{
	ldflags_save=$LDFLAGS
	cppflags_save=$CPPFLAGS

	if test "$with_libevent_ldflags" != ""; then
	   LDFLAGS=$with_libevent_ldflags
	fi
	if test "$with_libevent_cppflags" != ""; then
	   CPPFLAGS=$with_libevent_cppflags
	fi

	AC_CHECK_HEADER(event.h,
		[],
		[AC_MSG_ERROR([*** could not find libevent headers (see config.log for details) ***])],
		[
			#include <sys/time.h>
			#include <event.h>
		])

	AC_CHECK_LIB(event, event_init, [check_libevent_lib=-levent],		# found
		[AC_MSG_ERROR([*** could not find libasr library (see config.log for details) ***])],
		[])

	LDFLAGS=$ldflags_save
	CPPFLAGS=$cppflags_save
}])
