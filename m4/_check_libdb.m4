AC_DEFUN([WITH_LIBDB], [{
	AC_ARG_WITH([libdb],
		[  --with-libdb=PATH			Use libdb located in PATH],
		[
			with_libdb_include=${withval}
			if test -d "${with_libdb_include}/include"; then
				with_libdb_include="${with_libdb_include}/include"
			fi

			with_libdb_lib=${withval}
			if test -d "${with_libdb_lib}/lib"; then
				with_libdb_lib="${with_libdb_lib}/lib"
			fi

			with_libdb_cppflags="-I${with_libdb_include}"

			with_libdb_ldflags="-L${with_libdb_lib}"
			if test -n "${need_dash_r}"; then
				with_libdb_ldflags="${with_libdb_ldflags} -R${with_libdb_lib}"
			fi
		]
	)
}])

AC_DEFUN([CHECK_LIBDB], [{
	ldflags_save=$LDFLAGS
	cppflags_save=$CPPFLAGS

	if test "$with_libdb_ldflags" != ""; then
	   LDFLAGS=$with_libdb_ldflags
	fi
	if test "$with_libdb_cppflags" != ""; then
	   CPPFLAGS=$with_libdb_cppflags
	fi


	AC_CHECK_HEADER(db_185.h,
		[AC_DEFINE([HAVE_DB_185_H],	[], [if you have the <db_185.h> header file])],[
	AC_CHECK_HEADER(db.h,
		[AC_DEFINE([HAVE_DB_H],		[], [if you have the <db.h> header file])],[
 	AC_CHECK_HEADER(db1/db.h,
		[AC_DEFINE([HAVE_DB1_DB_H],	[], [if you have the <db1/db.h> header file])],[
	AC_MSG_ERROR([*** could not find libdb headers (see config.log for details) ***])])])])


	AC_CHECK_LIB(db, dbopen, [check_libdb_lib=-ldb],			# found
		[AC_CHECK_LIB(db1, dbopen, [check_libdb_lib=-ldb1],		# found
			[AC_CHECK_LIB(c, dbopen, [check_libdb_lib=-lc],		# found
		[AC_MSG_ERROR([*** could not find libdb library (see config.log for details) ***])],
		[])],
		[])],
		[])


	LDFLAGS=$ldflags_save
	CPPFLAGS=$cppflags_save
}])
