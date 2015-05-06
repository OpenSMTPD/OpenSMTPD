AC_DEFUN([WITH_LIBZ], [{
	AC_ARG_WITH([zlib],
		[  --with-zlib=PATH			Use zlib located in PATH],
		[
			with_zlib_include=${withval}
			if test -d "${with_zlib_include}/include"; then
				with_zlib_include="${with_zlib_include}/include"
			fi

			with_zlib_lib=${withval}
			if test -d "${with_zlib_lib}/lib"; then
				with_zlib_lib="${with_zlib_lib}/lib"
			fi

			with_zlib_cppflags="-I${with_zlib_include}"

			with_zlib_ldflags="-L${with_zlib_lib}"
			if test -n "${need_dash_r}"; then
				with_zlib_ldflags="${with_zlib_ldflags} -R${with_zlib_lib}"
			fi
		]
	)
}])

AC_DEFUN([CHECK_LIBZ], [{
	ldflags_save=$LDFLAGS
	cppflags_save=$CPPFLAGS
	libs_save=$LIBS

	if test "$with_zlib_ldflags" != ""; then
	   LDFLAGS=$with_zlib_ldflags
	fi
	if test "$with_zlib_cppflags" != ""; then
	   CPPFLAGS=$with_zlib_cppflags
	fi

	AC_CHECK_HEADER([zlib.h], [],
		[AC_MSG_ERROR([*** could not find zlib headers (see config.log for details) ***])])

	AC_CHECK_LIB(z, deflate, [check_zlib_lib=-lz],		# found
		[AC_MSG_ERROR([*** could not find zlib library (see config.log for details) ***])],
		[])

	LIBS="$LIBS -lz"
	AC_TRY_LINK_FUNC([deflate], [AC_DEFINE([HAVE_LIBZ])],
		[AC_MSG_ERROR([*** could not link to zlib (see config.log for details) ***])])


	LDFLAGS=$ldflags_save
	CPPFLAGS=$cppflags_save
	LIBS=$libs_save
}])
