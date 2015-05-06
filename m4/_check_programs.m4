AC_DEFUN([CHECK_PROGRAMS], [{
	AC_PROG_INSTALL
	AC_PROG_LIBTOOL
	AC_PATH_PROG([AR], [ar])
	AC_PATH_PROG([CAT], [cat])
	AC_PATH_PROG([SED], [sed])
	AC_PATH_PROG([TEST_MINUS_S_SH], [bash])
	AC_PATH_PROG([TEST_MINUS_S_SH], [ksh])
	AC_PATH_PROG([TEST_MINUS_S_SH], [sh])
	AC_PATH_PROG([SH], [sh])
	AC_PATH_PROG([GROFF], [groff])
	AC_PATH_PROG([NROFF], [nroff])
	AC_PATH_PROG([MANDOC], [mandoc])
	AC_PROG_YACC

	MANFMT="false"
	if test "x$MANDOC" != "x" ;
		MANFMT="$MANDOC"
	elif test "x$NROFF" != "x" ; then
		MANFMT="$NROFF -mandoc"
	elif test "x$GROFF" != "x" ; then
		MANFMT="$GROFF -mandoc -Tascii"
	else
		AC_MSG_WARN([no man page formatter found])
	fi
	AC_SUBST([MANFMT])
}])

