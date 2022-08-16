#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(libsecrm, 0.8, bogdandr@op.pl)
AM_INIT_AUTOMAKE
AC_CONFIG_FILES([Makefile src/Makefile doc/Makefile])
AC_CONFIG_SRCDIR([src/lsr_unlink.c])
AC_CONFIG_HEADER([config.h])

# ==================== Checks for programs.
AC_PROG_CC
AM_CONDITIONAL(ISGCC, test "x$ac_cv_c_compiler_gnu" = "xyes")
AC_PROG_LIBTOOL

# ==================== Checks for libraries.
AC_CHECK_LIB(dl,dlsym)
AC_CHECK_FUNCS([dlsym dlvsym])

if (test "x$ac_cv_lib_dl_dlsym" != "xyes"); then

#	AC_CHECK_FUNCS([dlsym dlvsym])
	if (test "x$ac_cv_func_dlsym" != "xyes" && test "x$ac_cv_func_dlvsym" != "xyes"); then

		AC_MSG_ERROR([[I need the dlsym() and optionally dlvsym() function to work.]])
	fi
fi

# ==================== Checks for header files.
AC_CHECK_HEADERS([dlfcn.h])

if (test "x$ac_cv_header_dlfcn_h" != "xyes"); then

	AC_MSG_ERROR([[I need the dlfcn.h file to work.]])
fi

AC_CHECK_DECLS([RTLD_NEXT],,,
	[
	#ifndef _GNU_SOURCE
	# define _GNU_SOURCE	1
	#endif
	#ifdef HAVE_DLFCN_H
	# include <dlfcn.h>
	#endif
	])

if (test "x$ac_cv_have_decl_RTLD_NEXT" != "xyes"); then

	echo "**************************************"
	AC_MSG_ERROR([[RTLD_NEXT not defined. Use the GNU C library. Sorry.]])
fi

AC_HEADER_STDC

AC_CHECK_HEADERS([stdlib.h string.h unistd.h errno.h malloc.h\
	time.h sys/stat.h sys/types.h stdarg.h fcntl.h libgen.h signal.h dirent.h])

AC_CHECK_DECLS([F_SETLEASE, F_SETSIG, F_GETSIG],,,
	[
	#ifndef _GNU_SOURCE
	# define _GNU_SOURCE	1
	#endif
	#ifdef HAVE_FCNTL_H
	# include <fcntl.h>
	#endif
	])

# ==================== Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_VOLATILE
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_CHECK_TYPES([off_t, size_t, long long, ssize_t, off64_t, mode_t],,,
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

AM_CONDITIONAL(HAS_LL, test "x$ac_cv_type_long_long" = "xyes")

if (test "x$ac_cv_c_compiler_gnu" = "xyes"); then

	AX_GCC_WARN_UNUSED_RESULT()

	AX_GCC_OPTION(CFLAGS, [[-Wall]], "$CFLAGS -Wall", "$CFLAGS")
	AX_GCC_OPTION(CFLAGS, [[-Wextra]], "$CFLAGS -Wextra", "$CFLAGS")
	AX_GCC_OPTION(CFLAGS, [[-W]], "$CFLAGS -W", "$CFLAGS")
	AX_GCC_OPTION(CFLAGS, [[-Wfloat-equal]], "$CFLAGS -Wfloat-equal", "$CFLAGS")
	AX_GCC_OPTION(CFLAGS, [[-Wbad-function-cast]], "$CFLAGS -Wbad-function-cast", "$CFLAGS")
	AX_GCC_OPTION(CFLAGS, [[-Wsign-compare]], "$CFLAGS -Wsign-compare", "$CFLAGS")
	AX_GCC_OPTION(CFLAGS, [[-Wunreachable-code]], "$CFLAGS -Wunreachable-code", "$CFLAGS")
	AX_GCC_OPTION(CFLAGS, [[-Wpointer-arith]], "$CFLAGS -Wpointer-arith", "$CFLAGS")
	AX_GCC_OPTION(CFLAGS, [[-Wcast-qual]], "$CFLAGS -Wcast-qual", "$CFLAGS")
	AX_GCC_OPTION(CFLAGS, [[-Wcast-align]], "$CFLAGS -Wcast-align", "$CFLAGS")
	AX_GCC_OPTION(CFLAGS, [[-Wstrict-prototypes]], "$CFLAGS -Wstrict-prototypes", "$CFLAGS")
	AX_GCC_OPTION(CFLAGS, [[-Wformat -Wformat-security]], "$CFLAGS -Wformat -Wformat-security", "$CFLAGS")
	AX_GCC_OPTION(CFLAGS, [[-Wformat -Wformat-nonliteral]], "$CFLAGS -Wformat -Wformat-nonliteral", "$CFLAGS")
	AX_GCC_OPTION(CFLAGS, [[-Wnested-externs]], "$CFLAGS -Wnested-externs", "$CFLAGS")
	AX_GCC_OPTION(CFLAGS, [[-Wshadow]], "$CFLAGS -Wshadow", "$CFLAGS")
	AX_GCC_OPTION(CFLAGS, [[-Wconversion]], "$CFLAGS -Wconversion", "$CFLAGS")
	AX_GCC_OPTION(CFLAGS, [[-Wdeclaration-after-statement]], "$CFLAGS -Wdeclaration-after-statement", "$CFLAGS")
	AX_GCC_OPTION(CFLAGS, [[-Wundef]], "$CFLAGS -Wundef", "$CFLAGS")
	AX_GCC_OPTION(CFLAGS, [[-Wpadded]], "$CFLAGS -Wpadded", "$CFLAGS")
	AX_GCC_OPTION(CFLAGS, [[-Wredundant-decls]], "$CFLAGS -Wredundant-decls", "$CFLAGS")
	AX_GCC_OPTION(CFLAGS, [[-Wfatal-errors]], "$CFLAGS -Wfatal-errors", "$CFLAGS")
	AX_GCC_OPTION(CFLAGS, [[-pedantic]], "$CFLAGS -pedantic", "$CFLAGS")
	AX_GCC_OPTION(CFLAGS, [[-Wno-strict-aliasing]], "$CFLAGS -Wno-strict-aliasing", "$CFLAGS")
	AX_GCC_OPTION(CFLAGS, [[-Wmissing-prototypes]], "$CFLAGS -Wmissing-prototypes", "$CFLAGS")
	AX_GCC_OPTION(CFLAGS, [[-Wmissing-declarations]], "$CFLAGS -Wmissing-declarations", "$CFLAGS")
	AX_GCC_OPTION(CFLAGS, [[-ffortify-source]], "$CFLAGS -ffortify-source", "$CFLAGS")

	if (test "x$ac_cv_type_long_long" = "xyes"); then

		AX_GCC_OPTION(CFLAGS, [[-std=gnu99]], "$CFLAGS -std=gnu99", "$CFLAGS")
	fi
fi

AC_SUBST(AM_CFLAGS,$CFLAGS)

# ==================== Checks for library functions.
AC_FUNC_MALLOC
AC_TYPE_SIGNAL

AC_CHECK_FUNCS([memcpy malloc random srandom snprintf lstat fstat \
	sigaction memset readlink renameat openat unlinkat])

if (test "x$ac_cv_func_malloc" != "xyes"); then

	AC_MSG_ERROR([[I need the malloc() function.]])
fi

if (test "x$ac_cv_type_signal" != "xvoid"); then

	AC_DEFINE([RETSIG_ISINT],[1], [Is return type of signal equal to int])
fi

AC_DEFINE_PATH_STYLE()

AC_OUTPUT

if (test "x$ac_cv_have_decl_F_GETSIG" != "xyes" || \
	test "x$ac_cv_have_decl_F_SETLEASE" != "xyes" || \
	test "x$ac_cv_have_decl_F_SETSIG" != "xyes"); then

	echo "**************************************"
	AC_MSG_WARN([[F_SETLEASE, F_GETSIG and/or F_SETSIG not defined. Not everything may work.]])
	AC_MSG_WARN([[Read the documentation docs/libsecrm.info on how to ban programs and files.]])
fi

if (test "x$ac_cv_header_dirent_h" != "xyes" || \
	test "x$ac_cv_header_sys_stat_h" != "xyes" || \
	! test -d "/proc" ); then

	echo "**************************************"
	AC_MSG_WARN([[Advanced file watching requires dirent.h, sys/stat.h headers
		and /proc to be mounted. Not everything may work.]])
	AC_MSG_WARN([[Read the documentation docs/libsecrm.info on how to ban programs and files.]])
fi
