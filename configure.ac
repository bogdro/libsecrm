#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
#
# LibSecRm - A library for secure removing files.
#	-- Makefile.am, part of the build system.
#
# Copyright (C) 2007-2024 Bogdan Drozdowski, bogdro (at) users . sourceforge . net
# License: GNU General Public License, v3+
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 3
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

AC_PREREQ([2.71])
AC_INIT([LibSecRm], [3.2], [bogdro@users.sourceforge.net], [libsecrm], [https://libsecrm.sourceforge.io])
AM_INIT_AUTOMAKE([-Wall])
AC_CONFIG_FILES([Makefile libsecrm.spec \
	doc/Makefile doc/libsecrm.texi doc/libsecrm.3 \
	src/Makefile src/lsr_cfg.h src/libsecrm.h src/lsr_public.c src/lsr_priv.h \
	libsecrm.pc test/Makefile])
AC_CONFIG_SRCDIR([src/lsr_unlink.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

# ==================== configure arguments

AC_ARG_ENABLE([random-method],
	AS_HELP_STRING([--enable-random-method],
		[Random pattern method (like shred) instead of full Gutmann @<:@default=no@:>@.]),
	[if (test "x$enableval" = "xyes"); then
		want_rand=yes
	 else
		want_rand=no
	 fi
	]
	,[want_rand=no])

if (test "x$want_rand" = "xyes"); then
	AC_DEFINE(LSR_WANT_RANDOM, [1], [If shred-like wiping method was chosen instead of full Gutmann method.])
fi

AC_ARG_ENABLE([last-zero],
	AS_HELP_STRING([--enable-last-zero],
		[Additional wiping with zeros @<:@default=no@:>@.]),
	[if (test "x$enableval" = "xyes"); then
		want_lastzero=yes
	 else
		want_lastzero=no
	 fi
	]
	,[want_lastzero=no])

if (test "x$want_lastzero" = "xyes"); then
	AC_DEFINE(LAST_PASS_ZERO, [1], [If an additional wiping with zeros is requested.])
fi

AC_ARG_ENABLE([all-zeros],
	AS_HELP_STRING([--enable-all-zeros],
		[Perform all wipings with zeros @<:@default=no@:>@.]),
	[if (test "x$enableval" = "xyes"); then
		want_allzeros=yes
	 else
		want_allzeros=no
	 fi
	]
	,[want_allzeros=no])

if (test "x$want_allzeros" = "xyes"); then
	AC_DEFINE(ALL_PASSES_ZERO, [1], [If all wipings should be done with zeros.])
fi

AC_ARG_ENABLE([public-interface],
	AS_HELP_STRING([--enable-public-interface],
		[Enable the library's public interface @<:@default=no@:>@.]),
	[if (test "x$enableval" = "xyes"); then
		public_if=yes
	 else
		public_if=no
	 fi
	]
	,[public_if=no])
#'
AM_CONDITIONAL(PUBLIC_INTERFACE, test "x$public_if" = "xyes")

AC_ARG_ENABLE([schneier-method],
	AS_HELP_STRING([--enable-schneier-method],
		[Schneier method instead of full Gutmann @<:@default=no@:>@.]),
	[if (test "x$enableval" = "xyes"); then
		want_schneier=yes
	 else
		want_schneier=no
	 fi
	]
	,[want_schneier=no])

if (test "x$want_schneier" = "xyes"); then
	AC_DEFINE(LSR_WANT_SCHNEIER, [1], [If Schneier wiping method was chosen instead of full Gutmann method.])
fi

AC_ARG_ENABLE([dod-method],
	AS_HELP_STRING([--enable-dod-method],
		[DoD method instead of full Gutmann @<:@default=no@:>@.]),
	[if (test "x$enableval" = "xyes"); then
		want_dod=yes
	 else
		want_dod=no
	 fi
	]
	,[want_dod=no])

if (test "x$want_dod" = "xyes"); then
	AC_DEFINE(LSR_WANT_DOD, [1], [If DoD wiping method was chosen instead of full Gutmann method.])
fi

AC_ARG_ENABLE([environment],
	AS_HELP_STRING([--enable-environment],
		[Enable additional ban files pointed to by environment variables @<:@default=yes@:>@.]),
        [if (test "x$enableval" = "xyes"); then
                environment=yes
         else
                environment=no
         fi
        ]
        ,[environment=yes])

if (test "x$environment" = "xyes"); then

	AC_DEFINE([LSR_ENABLE_ENV], [1],
		[Whether or not to enable additional ban files pointed to by environment variables.])
fi

AC_ARG_ENABLE([user-files],
	AS_HELP_STRING([--enable-user-files],
		[Enable additional ban files located in users' home directories @<:@default=yes@:>@.]),
        [if (test "x$enableval" = "xyes"); then
                user_files=yes
         else
                user_files=no
         fi
        ]
        ,[user_files=yes])

if (test "x$user_files" = "xyes"); then

	AC_DEFINE([LSR_ENABLE_USERBANS], [1],
		[Whether or not to enable additional ban files located in users' home directories.])
fi

intercept_malloc=no
AC_ARG_ENABLE([intercept-malloc],
	AS_HELP_STRING([--enable-intercept-malloc],
		[Enable intercepting the malloc() function @<:@default=no@:>@.]),
        [if (test "x$withval" != "x"); then
        	intercept_malloc=yes
		AC_DEFINE_UNQUOTED([LSR_INTERCEPT_MALLOC], [$withval],
			[Whether or not to intercept the malloc() function.])
         fi
        ])

AC_ARG_WITH([buffer-size],
	AS_HELP_STRING([--with-buffer-size=n],
		[Buffer size used for wiping, in bytes @<:@default=1024*1024@:>@.]),
        [if (test "x$withval" != "x"); then
		AC_DEFINE_UNQUOTED([LSR_BUF_SIZE], [$withval],
			[Buffer size used for wiping, in bytes.])
         fi
        ])

AC_ARG_WITH([passes],
	AS_HELP_STRING([--with-passes=n],
		[The number of passes used for wiping @<:@default is method-specific@:>@.]),
        [if (test "x$withval" != "x"); then
		AC_DEFINE_UNQUOTED([LSR_PASSES], [$withval],
			[The number of passes used for wiping.])
         fi
        ])

# ==================== Checks for programs.
AC_LANG(C)
AC_PROG_CC
AM_PROG_CC_C_O
AM_PROG_AR
AM_CONDITIONAL(ISGCC, test "x$GCC" = "xyes")
LT_INIT

# ==================== Checks for libraries.
libdl=yes
AC_CHECK_LIB([dl],[dlsym],,[libdl=no])
if (test "x$libdl" = "xyes"); then
	AC_DEFINE([HAVE_LIBDL], [1], [Whether you have the libdl library])
	AC_DEFINE([HAVE_LIBDL_DLSYM], [1], [Whether you have the dlsym() function in the libdl library])
	AC_CHECK_LIB([dl],[dlvsym],[AC_DEFINE([HAVE_LIBDL_DLVSYM], [1],
		[Whether you have the dlvsym() function in the libdl library])])

fi

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
	#define _GNU_SOURCE	1
	#endif
	#ifdef HAVE_DLFCN_H
	#include <dlfcn.h>
	#endif
	])

# AC_ HEADER_ STDC
# m4_warn([obsolete],
# [The preprocessor macro `STDC_HEADERS' is obsolete.
#   Except in unusual embedded environments, you can safely include all
#   ISO C90 headers unconditionally.])dnl
# Autoupdate added the next two lines to ensure that your configure
# script's behavior did not change.  They are probably safe to remove.
AC_CHECK_INCLUDES_DEFAULT
AC_PROG_EGREP

AC_CHECK_HEADERS([stdlib.h string.h unistd.h errno.h malloc.h\
	sys/types.h fcntl.h libgen.h signal.h stdint.h inttypes.h\
	linux/falloc.h sys/sysmacros.h stddef.h limits.h])

AC_CHECK_HEADER([stdarg.h],[AC_DEFINE([HAVE_STDARG_H], [1], [Whether you have the stdarg.h header])],
	[AC_CHECK_HEADER([varargs.h],[AC_DEFINE([HAVE_VARARGS_H], [1],
		[Whether you have the varargs.h header])])])

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
# AC_ HEADER_ TIME()
# m4_warn([obsolete],
# [Update your code to rely only on HAVE_SYS_TIME_H,
# then remove this warning and the obsolete code below it.
# All current systems provide time.h; it need not be checked for.
# Not all systems provide sys/time.h, but those that do, all allow
# you to include it and time.h simultaneously.])dnl
# AC_CHECK_HEADERS_ONCE([sys/time.h])
# Obsolete code to be removed.
# if test $ac_cv_header_sys_time_h = yes; then
#   AC_DEFINE([TIME_WITH_SYS_TIME],[1],[Define to 1 if you can safely include both <sys/time.h>
# 	     and <time.h>.  This macro is obsolete.])
# fi
# End of obsolete code.
AC_CHECK_HEADERS([sys/time.h time.h])
AC_HEADER_MAJOR

have_F_def=yes
AC_CHECK_DECLS([F_SETLEASE, F_SETSIG, F_GETSIG],,have_F_def=no,
	[
	#ifndef _GNU_SOURCE
	#define _GNU_SOURCE	1
	#endif
	#ifdef HAVE_FCNTL_H
	#include <fcntl.h>
	#endif
	])

# ==================== Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_VOLATILE
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_TYPE_LONG_LONG_INT
AC_TYPE_MODE_T
AC_TYPE_PID_T
AC_TYPE_SSIZE_T

have_ll=yes
AC_CHECK_TYPE([long long], [AC_DEFINE([HAVE_LONG_LONG], [1],
	[Whether you have the long long type])], [have_ll=no])
AC_CHECK_TYPES([off64_t, ino64_t, intptr_t, ptrdiff_t],,,
	[
	#define _FILE_OFFSET_BITS 64
	#define _LARGEFILE64_SOURCE
	#ifdef HAVE_SYS_TYPES_H
	#include <sys/types.h>
	#endif
	#ifdef HAVE_STDINT_H
	#include <stdint.h>
	#endif
	#ifdef HAVE_STDDEF_H
	#include <stddef.h>
	#endif
	#ifdef HAVE_INTTYPES_H
	#include <inttypes.h>
	#endif
	])
AC_CHECK_TYPES([sig_atomic_t],,,
	[
	#ifdef HAVE_SIGNAL_H
	#include <signal.h>
	#endif
	])

AM_CONDITIONAL([HAS_LL], [test "x$have_ll" = "xyes"])

# ==================== Checks for library functions.
AC_FUNC_MALLOC
# AC _TYPE _SIGNAL
# m4_warn([obsolete],
# [your code may safely assume C89 semantics that RETSIGTYPE is void.
# Remove this warning and the AC_CACHE_CHECK when you adjust the code.])dnl
AC_CACHE_CHECK([return type of signal handlers],[ac_cv_type_signal],[AC_COMPILE_IFELSE(
[AC_LANG_PROGRAM([#include <sys/types.h>
#include <signal.h>
],
		 [return *(signal (0, 0)) (0) == 1;])],
		   [ac_cv_type_signal=int],
		   [ac_cv_type_signal=void])])
AC_DEFINE_UNQUOTED([RETSIGTYPE],[$ac_cv_type_signal],[Define as the return type of signal handlers
		    (int or void).])

AC_CHECK_FUNCS([malloc memcpy random srandom snprintf stat lstat fstat \
	sigaction memset readlink renameat openat unlinkat memalign \
	posix_memalign fopen64 freopen64 open64 openat64 truncate64 \
	ftruncate64 creat64 sysconf getpagesize posix_fallocate fallocate \
	fallocate64 getenv basename symlink mkdir fstatat fstat64 \
	aligned_alloc stat64 lstat64 fstatat64 mkfifo posix_fallocate64 \
	pvalloc realpath canonicalize_file_name strtoul getpid])

AH_TEMPLATE([BRK_ARGTYPE])
AH_TEMPLATE([BRK_RETTYPE])
AC_CHECK_FUNC([brk], [AC_DEFINE(HAVE_BRK, [1], [Whether you have the brk function])
	AX_PROTOTYPE(brk,
	[
		#define _POSIX_C_SOURCE 199506L
		#define _XOPEN_SOURCE 500
		#define _XOPEN_SOURCE_EXTENDED 1
		#define _DEFAULT_SOURCE 1
		#ifdef HAVE_UNISTD_H
		#include <unistd.h>
		#endif
	],
	[
		RETTYPE (*test) (ARGTYPE) = &brk;
	],
	ARGTYPE, [void *, char *, int, const void *, const char *, const int],
	RETTYPE, [int, void *, char *])
	])

AH_TEMPLATE([SBRK_ARGTYPE])
AH_TEMPLATE([SBRK_RETTYPE])
AC_CHECK_FUNC([sbrk], [AC_DEFINE(HAVE_SBRK, [1], [Whether you have the sbrk function])
	AX_PROTOTYPE(sbrk,
	[
		#define _POSIX_C_SOURCE 199506L
		#define _XOPEN_SOURCE 500
		#define _XOPEN_SOURCE_EXTENDED 1
		#define _DEFAULT_SOURCE 1
		#ifdef HAVE_UNISTD_H
		#include <unistd.h>
		#endif
	],
	[
		RETTYPE (*test) (ARGTYPE) = &sbrk;
	],
	ARGTYPE, [intptr_t, int, ssize_t, ptrdiff_t, const intptr_t, const int, const ssize_t, const ptrdiff_t],
	RETTYPE, [void *, char *, int])
	])

AC_DEFINE_PATH_STYLE()
have_check=no
#ACTION-IF-NOT-FOUND is required, otherwise 'configure' fails
PKG_CHECK_MODULES([CHECK], [check >= 0.9.4], [have_check=yes], [have_check=no])
#AM_PATH_CHECK([], [have_check=yes])

AM_CONDITIONAL([LSR_TESTS_ENABLED], [test "x$have_check" = "xyes"])

# ==================== Checks for compiler options.

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
	AX_C_CHECK_FLAG([-Wformat -Wformat-overflow=2], [CFLAGS="$CFLAGS -Wformat -Wformat-overflow=2"], [CFLAGS="$CFLAGS"])
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
	AX_C_CHECK_FLAG([-O2], [CFLAGS="$CFLAGS -O2"], [CFLAGS="$CFLAGS"])
	AX_C_CHECK_FLAG([-O3], [CFLAGS="$CFLAGS -O3"], [CFLAGS="$CFLAGS"])
	#AX_C_CHECK_FLAG([-Os], [CFLAGS="$CFLAGS -O3"], [CFLAGS="$CFLAGS"])
        AX_C_CHECK_FLAG([-Waggregate-return], [CFLAGS="$CFLAGS -Waggregate-return"], [CFLAGS="$CFLAGS"])
        AX_C_CHECK_FLAG([-Wwrite-strings], [CFLAGS="$CFLAGS -Wwrite-strings"], [CFLAGS="$CFLAGS"])
        AX_C_CHECK_FLAG([-Wchkp], [CFLAGS="$CFLAGS -Wchkp"], [CFLAGS="$CFLAGS"])
        AX_C_CHECK_FLAG([-Wduplicated-cond], [CFLAGS="$CFLAGS -Wduplicated-cond"], [CFLAGS="$CFLAGS"])
        AX_C_CHECK_FLAG([-Wrestrict], [CFLAGS="$CFLAGS -Wrestrict"], [CFLAGS="$CFLAGS"])
        AX_C_CHECK_FLAG([-Woverlength-strings], [CFLAGS="$CFLAGS -Woverlength-strings"], [CFLAGS="$CFLAGS"])
        AX_C_CHECK_FLAG([-Wno-nonnull-compare], [CFLAGS="$CFLAGS -Wno-nonnull-compare"], [CFLAGS="$CFLAGS"])
        AX_C_CHECK_FLAG([-Wstringop-truncation], [CFLAGS="$CFLAGS -Wstringop-truncation"], [CFLAGS="$CFLAGS"])
        AX_C_CHECK_FLAG([-Wduplicated-branches], [CFLAGS="$CFLAGS -Wduplicated-branches"], [CFLAGS="$CFLAGS"])
        AX_C_CHECK_FLAG([-fstack-check], [CFLAGS="$CFLAGS -fstack-check"], [CFLAGS="$CFLAGS"])
        AX_C_CHECK_FLAG([-fanalyzer], [CFLAGS="$CFLAGS -fanalyzer"], [CFLAGS="$CFLAGS"])

        # required for the compiler, which is used by libtool instead of the linker
	AX_C_CHECK_FLAG([-Wl,-z -Wl,noexecstack], [CFLAGS="$CFLAGS -Wl,-z -Wl,noexecstack"], [CFLAGS="$CFLAGS"])
	# and just in case the linker was used
	AX_CHECK_LINK_FLAG([-z noexecstack])

	if (test "x$have_ll" = "xyes"); then

		AX_C_CHECK_FLAG([-std=gnu99], [CFLAGS="$CFLAGS -std=gnu99"], [CFLAGS="$CFLAGS"])
		AX_C_CHECK_FLAG([-Wno-long-long], [CFLAGS="$CFLAGS -Wno-long-long"], [CFLAGS="$CFLAGS"])
	fi
fi

# this doubles the CFLAGS on compile:
#AC_SUBST([AM_CFLAGS],[$CFLAGS])

# ==================== Output.

AC_OUTPUT

if (test "x$have_F_def" != "xyes"); then

	echo "**************************************"
	AC_MSG_WARN([[F_SETLEASE, F_GETSIG and/or F_SETSIG not defined. Not everything may work.]])
	AC_MSG_WARN([[Read the documentation doc/libsecrm.info on how to ban programs and files.]])
fi

if (test "x$has_dirent_h" != "xyes" || \
	test "x$has_sys_stat_h" != "xyes" || \
	! test -e "/proc" ); then

	echo "**************************************"
	AC_MSG_WARN([[Advanced file watching requires dirent.h, sys/stat.h headers
		and /proc to be mounted. Not everything may work.]])
	AC_MSG_WARN([[Read the documentation doc/libsecrm.info on how to ban programs and files.]])
fi

# ===================== Print summary

echo "***********************************"

if (test "x$want_rand" = "xyes"); then

	echo " *	Random pattern method instead of full Gutmann: yes"

else

	echo " *	Random pattern method instead of full Gutmann: no (default/disabled by command line)"

fi

if (test "x$want_lastzero" = "xyes"); then

	echo " *	Additional wiping with zeros: yes"

else

	echo " *	Additional wiping with zeros: no (default/disabled by command line)"

fi

if (test "x$want_allzeros" = "xyes"); then

	echo " *	Perform all wipings with zeros: yes"

else

	echo " *	Perform all wipings with zeros: no (default/disabled by command line)"

fi

if (test "x$want_schneier" = "xyes"); then

	echo " *	Schneier method instead of full Gutmann: yes"

else

	echo " *	Schneier method instead of full Gutmann: no (default/disabled by command line)"

fi

if (test "x$want_dod" = "xyes"); then

	echo " *	DoD method instead of full Gutmann: yes"

else

	echo " *	DoD method instead of full Gutmann: no (default/disabled by command line)"

fi

if (test "x$public_if" = "xyes"); then

	echo " *	Public interface: yes"

else

	echo " *	Public interface: no (default/disabled by command line)"

fi

if (test "x$environment" = "xyes"); then

	echo " *	Additional ban files pointed to by environment variables: yes"

else

	echo " *	Additional ban files pointed to by environment variables: no (disabled by command line)"

fi

if (test "x$user_files" = "xyes"); then

	echo " *	Additional ban files located in users' home directories: yes"

else

	echo " *	Additional ban files located in users' home directories: no (disabled by command line)"

fi

if (test "x$intercept_malloc" = "xyes"); then

	echo " *	Intercept malloc(): yes"

else

	echo " *	Intercept malloc(): no (default)"

fi

echo "***********************************"
