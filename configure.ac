#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(libsecrm, 0.1, bogdandr@op.pl)
AM_INIT_AUTOMAKE
AC_CONFIG_FILES([Makefile src/Makefile doc/Makefile])
AC_CONFIG_SRCDIR([src/lsr_unlink.c])
AC_CONFIG_HEADER([config.h])

# ==================== Checks for programs.
AC_PROG_CC
AM_CONDITIONAL(ISGCC, test $GCC == yes)
AC_DISABLE_STATIC
AM_DISABLE_STATIC
AC_PROG_LIBTOOL

# ==================== Checks for libraries.
AC_CHECK_LIB(dl,dlsym)

# ==================== Checks for header files.
AC_CHECK_HEADERS([dlfcn.h])

if test "$ac_cv_header_dlfcn_h" != yes; then
	AC_MSG_ERROR("I need the dlfcn.h file to work.")
fi

AC_HEADER_STDC

AC_CHECK_HEADERS([stdlib.h string.h unistd.h errno.h malloc.h\
	time.h sys/stat.h sys/types.h stdarg.h fcntl.h])

# ==================== Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_CHECK_TYPES([off_t, size_t, long long])

AM_CONDITIONAL(HAS_LL, test "$ac_cv_type_long_long" == yes)

# ==================== Checks for library functions.
AC_FUNC_MALLOC

AC_CHECK_FUNCS([memcpy malloc strtoul random srandom snprintf])

if test "$ac_cv_func_malloc" != yes; then
	AC_MSG_ERROR("I need the malloc() function.")
fi

AC_OUTPUT
