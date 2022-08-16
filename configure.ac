#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(libsecrm, 0.4, bogdandr@op.pl)
AM_INIT_AUTOMAKE
AC_CONFIG_FILES([Makefile src/Makefile doc/Makefile])
AC_CONFIG_SRCDIR([src/lsr_unlink.c])
AC_CONFIG_HEADER([config.h])

# ==================== Checks for programs.
AC_PROG_CC
AM_CONDITIONAL(ISGCC, test "$ac_cv_c_compiler_gnu" == yes)
AC_DISABLE_STATIC
AM_DISABLE_STATIC
AC_PROG_LIBTOOL

# ==================== Checks for libraries.
AC_CHECK_LIB(dl,dlsym)

if test "$ac_cv_lib_dl_dlsym" != yes; then
	AC_CHECK_FUNCS([dlsym dlvsym])
	if (test "$ac_cv_func_dlsym" != yes && test "$ac_cv_func_dlvsym" != yes); then
		AC_MSG_ERROR("I need the dlsym() and optionally dlvsym() function to work.")
	fi
fi

# ==================== Checks for header files.
AC_CHECK_HEADERS([dlfcn.h])

if test "$ac_cv_header_dlfcn_h" != yes; then
	AC_MSG_ERROR("I need the dlfcn.h file to work.")
fi

AC_HEADER_STDC

AC_CHECK_HEADERS([stdlib.h string.h unistd.h errno.h malloc.h\
	time.h sys/stat.h sys/types.h stdarg.h fcntl.h libgen.h])

# ==================== Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_CHECK_TYPES([off_t, size_t, long long])

AM_CONDITIONAL(HAS_LL, test "$ac_cv_type_long_long" == yes)

#if test "$ac_cv_c_compiler_gnu" == yes; then

#	AX_CFLAGS_GCC_OPTION(-Wall)
#	AX_CFLAGS_GCC_OPTION(-Wextra)
#	AX_CFLAGS_GCC_OPTION(-Wfloat-equal)
#	AX_CFLAGS_GCC_OPTION(-Wbad-function-cast)
#	AX_CFLAGS_GCC_OPTION(-Wsign-compare)
#	AX_CFLAGS_GCC_OPTION(-Wunreachable-code)
#	AX_CFLAGS_GCC_OPTION(-Wpointer-arith)
#	AX_CFLAGS_GCC_OPTION(-Wcast-qual)
#	AX_CFLAGS_GCC_OPTION(-Wcast-align)
#	AX_CFLAGS_GCC_OPTION(-Wstrict-prototypes)
#	AX_CFLAGS_GCC_OPTION(-Wformat-security)
#	AX_CFLAGS_GCC_OPTION(-Wformat-nonliteral)
#	AX_CFLAGS_GCC_OPTION(-Wnested-externs)
#	AX_CFLAGS_GCC_OPTION(-Wshadow)
#	AX_CFLAGS_GCC_OPTION(-Wconversion)
#	AX_CFLAGS_GCC_OPTION(-Wdeclaration-after-statement)
#	AX_CFLAGS_GCC_OPTION(-Wundef)
#	AX_CFLAGS_GCC_OPTION(-Wpadded)
#	AX_CFLAGS_GCC_OPTION(-Wredundant-decls)
#	AX_CFLAGS_GCC_OPTION(-Wfatal-errors)
#	AX_CFLAGS_GCC_OPTION(-pedantic)

#	if test "$ac_cv_type_long_long" == yes; then
#		AX_CFLAGS_GCC_OPTION(-std=gnu99)
#	fi
#fi

# ==================== Checks for library functions.
AC_FUNC_MALLOC

AC_CHECK_FUNCS([memcpy malloc strtoul random srandom snprintf lstat fstat fseeko ftello])

if test "$ac_cv_func_malloc" != yes; then
	AC_MSG_ERROR("I need the malloc() function.")
fi

AC_OUTPUT
