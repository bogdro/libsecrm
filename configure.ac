#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(libsecrm, 1.0, bogdandr@op.pl)
AM_INIT_AUTOMAKE
AC_CONFIG_FILES([Makefile src/Makefile doc/Makefile])
AC_CONFIG_SRCDIR([src/lsr_unlink.c])
AC_CONFIG_HEADER([config.h])

# ==================== configure arguments

AC_ARG_ENABLE(LSR_WANT_RANDOM,[[  --enable-random-method	Random pattern method (like shred) instead of full Gutmann.]],
	[if (test "x$enableval" = "xyes"); then
		want_rand=yes
	 else
		want_rand=no
	 fi
	]
	,want_rand=no)

if (test "x$want_rand" = "xyes"); then
	AC_DEFINE(LSR_WANT_RANDOM, [1], [If shred-like wiping method was chosen instead of full Gutmann method.])
fi

# ==================== Checks for programs.
AC_PROG_CC
AM_CONDITIONAL(ISGCC, test "x$GCC" = "xyes")
AC_PROG_LIBTOOL

# ==================== Checks for libraries.
libdl=yes
AC_CHECK_LIB([dl],[dlsym],
	[AC_DEFINE([HAVE_LIBDL], [1], [Whether you have the libdl library])],[libdl=no])
dlsym=yes
AC_CHECK_FUNC([dlsym],
	[AC_DEFINE([HAVE_DLSYM], [1], [Whether you have the dlsym function])],[dlsym=no])
dlvsym=yes
AC_CHECK_FUNC([dlvsym],
	[AC_DEFINE([HAVE_DLVSYM], [1], [Whether you have the dlvsym function])],[dlvsym=no])

if (test "x$libdl" != "xyes"); then

#	AC_CHECK_FUNCS([dlsym dlvsym])
	if (test "x$dlsym" != "xyes" && test "x$dlvsym" != "xyes"); then

		AC_MSG_ERROR([[I need the dlsym() and optionally dlvsym() function to work.]])
	fi
fi

# ==================== Checks for header files.
AC_CHECK_HEADER([dlfcn.h],[AC_DEFINE([HAVE_DLFCN_H], [1], [Whether you have the dlfcn.h header])],
	AC_MSG_ERROR([[I need the dlfcn.h file to work.]]), [])

AC_CHECK_DECL([RTLD_NEXT],[AC_DEFINE([HAVE_DECL_RTLD_NEXT], [1], [Whether RTLD_NEXT is defined])],
	[echo "**************************************"
	AC_MSG_ERROR([[RTLD_NEXT not defined. Use the GNU C library. Sorry.]])],
	[
	#ifndef _GNU_SOURCE
	# define _GNU_SOURCE	1
	#endif
	#ifdef HAVE_DLFCN_H
	# include <dlfcn.h>
	#endif
	])

AC_HEADER_STDC

AC_CHECK_HEADERS([stdlib.h string.h unistd.h errno.h malloc.h\
	sys/types.h stdarg.h fcntl.h libgen.h signal.h])

AC_HEADER_DIRENT

has_dirent_h=yes
AC_CHECK_HEADER([dirent.h],AC_DEFINE([HAVE_DIRENT_H],[1],
	[Whether you have the dirent.h header.]),
		[AC_CHECK_HEADER([sys/ndir.h],AC_DEFINE([HAVE_SYS_NDIR_H],[1],
		[Whether you have the sys/ndir.h header.]),
			[AC_CHECK_HEADER([sys/ndir.h],AC_DEFINE([HAVE_SYS_NDIR_H],[1],
			[Whether you have the sys/ndir.h header.]),
				[AC_CHECK_HEADER([sys/dir.h],AC_DEFINE([HAVE_SYS_DIR_H],[1],
				[Whether you have the sys/dir.h header.]),
					[AC_CHECK_HEADER([ndir.h],AC_DEFINE([HAVE_NDIR_H],[1],
					[Whether you have the ndir.h header.]),
						[has_dirent_h=no])])])])])

has_sys_stat_h=yes
AC_CHECK_HEADER([sys/stat.h],AC_DEFINE([HAVE_SYS_STAT_H],[1],
	[Whether you have the sys/stat.h header.]),[has_sys_stat_h=no])

AC_HEADER_STAT
AC_HEADER_TIME
AC_CHECK_HEADERS([sys/time.h time.h])
AC_HEADER_MAJOR

have_F_def=yes
AC_CHECK_DECLS([F_SETLEASE, F_SETSIG, F_GETSIG],,have_F_def=no,
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

have_ll=yes
AC_CHECK_TYPE([long long], [AC_DEFINE([HAVE_LONG_LONG], [1],
	[Whether you have the long long type])], [have_ll=no])
AC_CHECK_TYPES([off_t, size_t, ssize_t, off64_t, mode_t],,,
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

AM_CONDITIONAL([HAS_LL], [test "x$have_ll" = "xyes"])

if (test "x$GCC" = "xyes" ); then

	AX_GCC_WARN_UNUSED_RESULT()

	AX_C_CHECK_FLAG([-Wall], [CFLAGS="$CFLAGS -Wall"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wextra], [CFLAGS="$CFLAGS -Wextra"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-W], [CFLAGS="$CFLAGS -W"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wfloat-equal], [CFLAGS="$CFLAGS -Wfloat-equal"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wbad-function-cast], [CFLAGS="$CFLAGS -Wbad-function-cast"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wsign-compare], [CFLAGS="$CFLAGS -Wsign-compare"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wunreachable-code], [CFLAGS="$CFLAGS -Wunreachable-code"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wpointer-arith], [CFLAGS="$CFLAGS -Wpointer-arith"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wcast-qual], [CFLAGS="$CFLAGS -Wcast-qual"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wcast-align], [CFLAGS="$CFLAGS -Wcast-align"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wstrict-prototypes], [CFLAGS="$CFLAGS -Wstrict-prototypes"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wformat -Wformat-security], [CFLAGS="$CFLAGS -Wformat -Wformat-security"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wformat -Wformat-nonliteral], [CFLAGS="$CFLAGS -Wformat -Wformat-nonliteral"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wnested-externs], [CFLAGS="$CFLAGS -Wnested-externs"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wshadow], [CFLAGS="$CFLAGS -Wshadow"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wconversion], [CFLAGS="$CFLAGS -Wconversion"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wdeclaration-after-statement], [CFLAGS="$CFLAGS -Wdeclaration-after-statement"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wundef], [CFLAGS="$CFLAGS -Wundef"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wpadded], [CFLAGS="$CFLAGS -Wpadded"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wredundant-decls], [CFLAGS="$CFLAGS -Wredundant-decls"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wfatal-errors], [CFLAGS="$CFLAGS -Wfatal-errors"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-pedantic], [CFLAGS="$CFLAGS -pedantic"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wno-strict-aliasing], [CFLAGS="$CFLAGS -Wno-strict-aliasing"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wmissing-prototypes], [CFLAGS="$CFLAGS -Wmissing-prototypes"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wmissing-declarations], [CFLAGS="$CFLAGS -Wmissing-declarations"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-O1 -Wuninitialized], [CFLAGS="$CFLAGS -O1 -Wuninitialized"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Winit-self], [CFLAGS="$CFLAGS -Winit-self"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-Wlogical-op], [CFLAGS="$CFLAGS -Wlogical-op"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-fstack-protector-all], [CFLAGS="$CFLAGS -fstack-protector-all"], [CFLAGS="$CFLAGS"])

	if (test "x$have_ll" = "xyes"); then

		AX_C_CHECK_FLAG([-std=gnu99], [CFLAGS="$CFLAGS -std=gnu99"], [CFLAGS="$CFLAGS"])
		AX_C_CHECK_FLAG([-Wno-long-long], [CFLAGS="$CFLAGS -Wno-long-long"], [CFLAGS="$CFLAGS"])
	fi
fi

AC_SUBST([AM_CFLAGS],[$CFLAGS])

# ==================== Checks for library functions.
AC_FUNC_MALLOC
AC_TYPE_SIGNAL

malloc=yes
AC_CHECK_FUNC([malloc],
	[AC_DEFINE(HAVE_MALLOC, [1], [Whether you have the malloc function])],[malloc=no])

AC_CHECK_FUNCS([memcpy random srandom snprintf lstat fstat \
	sigaction memset readlink renameat openat unlinkat])

if (test "x$malloc" != "xyes"); then

	AC_MSG_ERROR([[I need the malloc() function.]])
fi

AC_DEFINE_PATH_STYLE()

AC_OUTPUT

if (test "x$have_F_def" != "xyes"); then

	echo "**************************************"
	AC_MSG_WARN([[F_SETLEASE, F_GETSIG and/or F_SETSIG not defined. Not everything may work.]])
	AC_MSG_WARN([[Read the documentation docs/libsecrm.info on how to ban programs and files.]])
fi

if (test "x$has_dirent_h" != "xyes" || \
	test "x$has_sys_stat_h" != "xyes" || \
	! test -e "/proc/cpuinfo" ); then

	echo "**************************************"
	AC_MSG_WARN([[Advanced file watching requires dirent.h, sys/stat.h headers
		and /proc to be mounted. Not everything may work.]])
	AC_MSG_WARN([[Read the documentation docs/libsecrm.info on how to ban programs and files.]])
fi
