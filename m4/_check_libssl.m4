AC_DEFUN([WITH_LIBSSL], [{
	AC_ARG_WITH([libssl],
		[  --with-libssl=PATH			Use libssl located in PATH],
		[
			with_libssl_include=${withval}
			if test -d "${with_libssl_include}/include"; then
				with_libssl_include="${with_libssl_include}/include"
			fi

			with_libssl_lib=${withval}
			if test -d "${with_libssl_lib}/lib"; then
				with_libssl_lib="${with_libssl_lib}/lib"
			fi

			with_libssl_cppflags="-I${with_libssl_include}"

			with_libssl_ldflags="-L${with_libssl_lib}"
			if test -n "${need_dash_r}"; then
				with_libssl_ldflags="${with_libssl_ldflags} -R${with_libssl_lib}"
			fi
		]
	)
}])

AC_DEFUN([CHECK_LIBSSL], [{
	ldflags_save=$LDFLAGS
	cppflags_save=$CPPFLAGS
	libs_save=$LIBS

	if test "$with_libssl_ldflags" != ""; then
	   LDFLAGS=$with_libssl_ldflags
	fi
	if test "$with_libssl_cppflags" != ""; then
	   CPPFLAGS=$with_libssl_cppflags
	fi

	AC_MSG_CHECKING([if SSL library is LibreSSL or OpenSSL])
	AC_LINK_IFELSE(
		[AC_LANG_PROGRAM([[ #include <openssl/opensslv.h> ]],
		[[ { int x = LIBRESSL_VERSION_NUMBER;} ]])],
		[
			AC_MSG_RESULT([LibreSSL, you deserve a cookie :-)])
		],[
			AC_MSG_RESULT([OpenSSL, so sorry :-(])
		]
	)

	AC_MSG_CHECKING([if programs using LibreSSL functions will link])
	AC_LINK_IFELSE(
		[AC_LANG_PROGRAM([[ #include <openssl/evp.h> ]],
		[[ SSLeay_add_all_algorithms(); ]])],
		[
			AC_MSG_RESULT([yes])
			check_libssl_lib="-lcrypto"
		],[
			AC_MSG_RESULT([no])
			LIBS="$LIBS -ldl"
			AC_MSG_CHECKING([if programs using LibreSSL need -ldl])
			AC_LINK_IFELSE(
				[AC_LANG_PROGRAM([[ #include <openssl/evp.h>]],
				[[ SSLeay_add_all_algorithms(); ]])],
				[
					AC_MSG_RESULT([yes])
				],[
					AC_MSG_RESULT([no])
					check_libssl_lib="-lcrypto -ld"
				]
			)
		]
	)


	LDFLAGS=$ldflags_save
	CPPFLAGS=$cppflags_save
	LIBS=$libs_save
}])
