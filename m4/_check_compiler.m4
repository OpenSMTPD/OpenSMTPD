AC_DEFUN([CHECK_COMPILER], [{

if test "$GCC" = "yes" || test "$GCC" = "egcs"; then
   	OPENSMTPD_CHECK_CFLAG_COMPILE([-Qunused-arguments])
	OPENSMTPD_CHECK_CFLAG_COMPILE([-Wunknown-warning-option])
	OPENSMTPD_CHECK_CFLAG_COMPILE([-Wall])
	OPENSMTPD_CHECK_CFLAG_COMPILE([-Wpointer-arith])
	OPENSMTPD_CHECK_CFLAG_COMPILE([-Wuninitialized])
	OPENSMTPD_CHECK_CFLAG_COMPILE([-Wsign-compare])
	OPENSMTPD_CHECK_CFLAG_COMPILE([-Wformat-security])
	OPENSMTPD_CHECK_CFLAG_COMPILE([-Wsizeof-pointer-memaccess])
	OPENSMTPD_CHECK_CFLAG_COMPILE([-Wpointer-sign], [-Wno-pointer-sign])
	OPENSMTPD_CHECK_CFLAG_COMPILE([-Wunused-result], [-Wno-unused-result])
	OPENSMTPD_CHECK_CFLAG_COMPILE([-fno-strict-aliasing])
	OPENSMTPD_CHECK_CFLAG_COMPILE([-D_FORTIFY_SOURCE=2])
    if test "x$use_toolchain_hardening" = "x1"; then
	OPENSMTPD_CHECK_LDFLAG_LINK([-Wl,-z,relro])
	OPENSMTPD_CHECK_LDFLAG_LINK([-Wl,-z,now])
	OPENSMTPD_CHECK_LDFLAG_LINK([-Wl,-z,noexecstack])
		# NB. -ftrapv expects certain support functions to be present in
	# the compiler library (libgcc or similar) to detect integer operations
	# that can overflow. We must check that the result of enabling it
	# actually links. The test program compiled/linked includes a number
	# of integer operations that should exercise this.
	OPENSMTPD_CHECK_CFLAG_LINK([-ftrapv])
    fi
    	AC_MSG_CHECKING([gcc version])
	GCC_VER=`$CC -v 2>&1 | $AWK '/gcc version /{print $3}'`
	case $GCC_VER in
		1.*) no_attrib_nonnull=1 ;;
		2.8* | 2.9*)
		     no_attrib_nonnull=1
		     ;;
		2.*) no_attrib_nonnull=1 ;;
		*) ;;
	esac
	AC_MSG_RESULT([$GCC_VER])

	AC_MSG_CHECKING([if $CC accepts -fno-builtin-memset])
	saved_CFLAGS="$CFLAGS"
	CFLAGS="$CFLAGS -fno-builtin-memset"
	AC_LINK_IFELSE([AC_LANG_PROGRAM([[ #include <string.h> ]],
			[[ char b[10]; memset(b, 0, sizeof(b)); ]])],
		[ AC_MSG_RESULT([yes]) ],
		[ AC_MSG_RESULT([no])
		  CFLAGS="$saved_CFLAGS" ]
	)

	# -fstack-protector-all doesn't always work for some GCC versions
	# and/or platforms, so we test if we can.  If it's not supported
	# on a given platform gcc will emit a warning so we use -Werror.
	if test "x$use_stack_protector" = "x1"; then
	    for t in -fstack-protector-strong -fstack-protector-all \
		    -fstack-protector; do
		AC_MSG_CHECKING([if $CC supports $t])
		saved_CFLAGS="$CFLAGS"
		saved_LDFLAGS="$LDFLAGS"
		CFLAGS="$CFLAGS $t -Werror"
		LDFLAGS="$LDFLAGS $t -Werror"
		AC_LINK_IFELSE(
			[AC_LANG_PROGRAM([[ #include <stdio.h> ]],
			[[
	char x[256];
	snprintf(x, sizeof(x), "XXX");
			 ]])],
		    [ AC_MSG_RESULT([yes])
		      CFLAGS="$saved_CFLAGS $t"
		      LDFLAGS="$saved_LDFLAGS $t"
		      AC_MSG_CHECKING([if $t works])
		      AC_RUN_IFELSE(
			[AC_LANG_PROGRAM([[ #include <stdio.h> ]],
			[[
	char x[256];
	snprintf(x, sizeof(x), "XXX");
			]])],
			[ AC_MSG_RESULT([yes])
			  break ],
			[ AC_MSG_RESULT([no]) ],
			[ AC_MSG_WARN([cross compiling: cannot test])
			  break ]
		      )
		    ],
		    [ AC_MSG_RESULT([no]) ]
		)
		CFLAGS="$saved_CFLAGS"
		LDFLAGS="$saved_LDFLAGS"
	    done
	fi

	if test -z "$have_llong_max"; then
		# retry LLONG_MAX with -std=gnu99, needed on some Linuxes
		unset ac_cv_have_decl_LLONG_MAX
		saved_CFLAGS="$CFLAGS"
		CFLAGS="$CFLAGS -std=gnu99"
		AC_CHECK_DECL([LLONG_MAX],
		    [have_llong_max=1],
		    [CFLAGS="$saved_CFLAGS"],
		    [#include <limits.h>]
		)
	fi
fi


AC_MSG_CHECKING([if compiler allows __attribute__ on return types])
AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM([[
#include <stdlib.h>
__attribute__((__unused__)) static void foo(void){return;}]],
    [[ exit(0); ]])],
    [ AC_MSG_RESULT([yes]) ],
    [ AC_MSG_RESULT([no])
      AC_DEFINE(NO_ATTRIBUTE_ON_RETURN_TYPE, 1,
	 [compiler does not accept __attribute__ on return types]) ]
)

if test "x$no_attrib_nonnull" != "x1" ; then
	AC_DEFINE([HAVE_ATTRIBUTE__NONNULL__], [1], [Have attribute nonnull])
fi

AC_MSG_CHECKING([compiler and flags for sanity])
AC_RUN_IFELSE([AC_LANG_PROGRAM([[ #include <stdio.h> ]], [[ exit(0); ]])],
	[	AC_MSG_RESULT([yes]) ],
	[
		AC_MSG_RESULT([no])
		AC_MSG_ERROR([*** compiler cannot create working executables, check config.log ***])
	],
	[	AC_MSG_WARN([cross compiling: not checking compiler sanity]) ]
)



}])

