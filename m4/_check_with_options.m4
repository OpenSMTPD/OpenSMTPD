AC_DEFUN([CHECK_WITH_OPTIONS], [{
AC_ARG_WITH([rpath],
	[  --without-rpath         Disable auto-added -R linker paths],
	[
		if test "x$withval" = "xno" ; then
			need_dash_r=""
		fi
		if test "x$withval" = "xyes" ; then
			need_dash_r=1
		fi
	]
)

AC_ARG_WITH([cflags],
	[  --with-cflags           Specify additional flags to pass to compiler],
	[
		if test -n "$withval" && test "x$withval" != "xno" &&  \
		    test "x${withval}" != "xyes"; then
			CFLAGS="$CFLAGS $withval"
		fi
	]
)
AC_ARG_WITH([cppflags],
	[  --with-cppflags         Specify additional flags to pass to preprocessor] ,
	[
		if test -n "$withval" && test "x$withval" != "xno" &&  \
		    test "x${withval}" != "xyes"; then
			CPPFLAGS="$CPPFLAGS $withval"
		fi
	]
)
AC_ARG_WITH([ldflags],
	[  --with-ldflags          Specify additional flags to pass to linker],
	[
		if test -n "$withval" && test "x$withval" != "xno" &&  \
		    test "x${withval}" != "xyes"; then
			LDFLAGS="$LDFLAGS $withval"
		fi
	]
)
AC_ARG_WITH([libs],
	[  --with-libs             Specify additional libraries to link with],
	[
		if test -n "$withval" && test "x$withval" != "xno" &&  \
		    test "x${withval}" != "xyes"; then
			LIBS="$LIBS $withval"
		fi
	]
)
AC_ARG_WITH([Werror],
	[  --with-Werror           Build main code with -Werror],
	[
		if test -n "$withval" && test "x$withval" != "xno"; then
			cflags_werror="-Werror"
			if test "x${withval}" != "xyes"; then
				cflags_werror="$withval"
			fi
		fi
	]
)
}])

