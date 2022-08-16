/*
 * A library for secure removing files.
 *	-- configuration header file.
 *
 * Copyright (C) 2007 Bogdan Drozdowski, bogdandr (at) op.pl
 * License: GNU General Public License, v3+
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 3
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foudation:
 *		Free Software Foundation
 *		51 Franklin Street, Fifth Floor
 *		Boston, MA 02110-1301
 *		USA
 */

#ifndef LSR_CFG_H
# define LSR_CFG_H		1

# ifdef HAVE_CONFIG_H
#  include <config.h>
# else
#  define HAVE_DECL_F_GETSIG	1
#  define HAVE_DECL_F_SETLEASE	1
#  define HAVE_DECL_F_SETSIG	1
#  define HAVE_DECL_RTLD_NEXT	1
#  define HAVE_DLFCN_H		1
#  define HAVE_DLSYM		1
#  define HAVE_DLVSYM		1
#  define HAVE_ERRNO_H		1
#  define HAVE_FCNTL_H		1
#  define HAVE_FSTAT		1
#  define HAVE_LIBDL		1
#  define HAVE_LIBGEN_H		1
#  define HAVE_LONG_LONG	1
#  define HAVE_LSTAT		1
#  define HAVE_MALLOC		1
#  define HAVE_MALLOC_H		1
#  define HAVE_MEMCPY		1
#  define HAVE_MEMORY_H		1
#  define HAVE_MEMSET		1
#  define HAVE_MODE_T		1
#  define HAVE_OFF_T		1
#  define HAVE_OFF64_T		1
#  define HAVE_RANDOM		1
#  define HAVE_READLINK		1
#  undef  HAVE_RENAMEAT
#  define HAVE_SIGACTION	1
#  define HAVE_SIGNAL_H		1
#  define HAVE_SIG_ATOMIC_T	1
#  define HAVE_SIZE_T		1
#  define HAVE_SNPRINTF		1
#  define HAVE_SRANDOM		1
#  define HAVE_SSIZE_T		1
#  define HAVE_STDARG_H		1
#  define HAVE_STDINT_H		1
#  define HAVE_STDLIB_H		1
#  define HAVE_STRING_H		1
#  define HAVE_STRTOUL		1
#  define HAVE_SYS_STAT_H	1
#  define HAVE_SYS_TYPES_H	1
#  define HAVE_TIME_H		1
#  define HAVE_UNISTD_H		1

#  define GCC_WARN_UNUSED_RESULT LSR_ATTR((warn_unused_result))

/* path style 16=dos 32=unix 64=url 128=mac */
#  define PATH_STYLE		32
#  define RETSIGTYPE		void

#  define STDC_HEADERS		1

#  define PACKAGE_NAME		"libsecrm"
#  define PACKAGE		PACKAGE_NAME
#  define PACKAGE_VERSION	"0.7"
#  define VERSION		PACKAGE_VERSION
# endif

#endif	/* LSR_CFG_H */
