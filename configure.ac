#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(libsecrm, 0.6, bogdandr@op.pl)
AM_INIT_AUTOMAKE
AC_CONFIG_FILES([Makefile src/Makefile doc/Makefile])
AC_CONFIG_SRCDIR([src/lsr_unlink.c])
AC_CONFIG_HEADER([config.h])

# ==================== Checks for programs.
AC_PROG_CC
AM_CONDITIONAL(ISGCC, test "x$ac_cv_c_compiler_gnu" = xyes)
AC_DISABLE_STATIC
AM_DISABLE_STATIC
AC_PROG_LIBTOOL

# ==================== Checks for libraries.
AC_CHECK_LIB(dl,dlsym)
AC_CHECK_FUNCS([dlsym dlvsym])

if test "x$ac_cv_lib_dl_dlsym" != xyes; then
#	AC_CHECK_FUNCS([dlsym dlvsym])
	if (test "x$ac_cv_func_dlsym" != xyes && test "x$ac_cv_func_dlvsym" != xyes); then
		AC_MSG_ERROR("I need the dlsym() and optionally dlvsym() function to work.")
	fi
fi

# ==================== Checks for header files.
AC_CHECK_HEADERS([dlfcn.h])

if test "x$ac_cv_header_dlfcn_h" != xyes; then
	AC_MSG_ERROR("I need the dlfcn.h file to work.")
fi

AC_HEADER_STDC

AC_CHECK_HEADERS([stdlib.h string.h unistd.h errno.h malloc.h\
	time.h sys/stat.h sys/types.h stdarg.h fcntl.h libgen.h signal.h])

# ==================== Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_VOLATILE
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_CHECK_TYPES([off_t, size_t, long long, ssize_t, off64_t],,,
	[
	#define _FILE_OFFSET_BITS 64
	#define _LARGEFILE64_SOURCE
	#ifdef HAVE_SYS_TYPES_H
	# include <sys/types.h>
	#endif
	])
AC_CHECK_TYPES([sig_atomic_t],,,
	[
	#ifdef HAVE_SIGNAL_H
	# include <signal.h>
	#endif
	])

AM_CONDITIONAL(HAS_LL, test "x$ac_cv_type_long_long" = xyes)

#if test "x$ac_cv_c_compiler_gnu" = xyes; then

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

#	if test "x$ac_cv_type_long_long" = xyes; then
#		AX_CFLAGS_GCC_OPTION(-std=gnu99)
#	fi
#fi

# ==================== Checks for library functions.
AC_FUNC_MALLOC
AC_TYPE_SIGNAL

AC_CHECK_FUNCS([memcpy malloc strtoul random srandom snprintf lstat fstat fseeko ftello \
	sigaction memset readlink])

if test "x$ac_cv_func_malloc" != xyes; then
	AC_MSG_ERROR("I need the malloc() function.")
fi

if test "x$ac_cv_type_signal" != xvoid; then
	AC_DEFINE([RETSIG_ISINT],[1], [Is return type of signal equal to int])
fi

AC_OUTPUT
