/*
 * LibSecRm - A library for secure removing files.
 *	-- file opening functions' replacements.
 *
 * Copyright (C) 2007-2022 Bogdan Drozdowski, bogdro (at) users . sourceforge . net
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "lsr_cfg.h"

#define _LARGEFILE64_SOURCE 1
#define _ATFILE_SOURCE 1

#ifdef HAVE_STDARG_H
# include <stdarg.h>
#else
# ifdef HAVE_VARARGS_H
#  include <varargs.h>
# endif
#endif

#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#else
# define O_WRONLY	1
# define O_RDWR		2
# define O_TRUNC	01000
#endif

#ifndef O_EXCL
# define O_EXCL		0200
#endif

#ifdef HAVE_STRING_H
# if (!defined STDC_HEADERS) && (defined HAVE_MEMORY_H)
#  include <memory.h>
# endif
# include <string.h>
#endif

#include <stdio.h>

#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#else
# define S_IRUSR 0600
# define S_IWUSR 0400
#endif

#include "lsr_priv.h"

#ifdef __GNUC__
# ifndef unlink
#  pragma GCC poison unlink
# endif
# ifndef unlinkat
#  pragma GCC poison unlinkat
# endif
# ifndef remove
#  pragma GCC poison remove
# endif
# ifndef truncate
#  pragma GCC poison truncate
# endif
# ifndef ftruncate
#  pragma GCC poison ftruncate
# endif
# ifndef truncate64
#  pragma GCC poison truncate64
# endif
# ifndef ftruncate64
#  pragma GCC poison ftruncate64
# endif
#endif

/*
#ifdef __cplusplus
extern "C" {
#endif

#ifndef HAVE_FOPEN64
extern FILE* fopen64 LSR_PARAMS((const char * const name, const char * const mode));
#endif
#ifndef HAVE_FREOPEN64
extern FILE* freopen64 LSR_PARAMS((const char * const path, const char * const mode, FILE * stream));
#endif
#ifndef HAVE_OPEN64
extern int open64 LSR_PARAMS((const char * const path, const int flags, ... ));
#endif

#ifdef __cplusplus
}
#endif
*/

/* lsr_priv.h:
#ifndef HAVE_OPENAT64
# ifdef __cplusplus
extern "C" {
# endif

extern int openat64 LSR_PARAMS((const int dirfd, const char * const pathname, const int flags, ...));

# ifdef __cplusplus
}
# endif

#endif
*/

#ifdef TEST_COMPILE
# ifdef LSR_ANSIC
#  define WAS_LSR_ANSIC
# endif
# undef LSR_ANSIC
#endif

/* ======================================================= */

#ifndef LSR_ANSIC
static FILE* generic_fopen LSR_PARAMS((
	const char * const name, const char * const mode,
	const fp_cp_cp real_fopen, const i_cp_i_ real_open));
#endif

static FILE*
generic_fopen (
#ifdef LSR_ANSIC
	const char * const name, const char * const mode,
	const fp_cp_cp real_fopen, const i_cp_i_ real_open)
#else
	name, mode, real_fopen, real_open)
	const char * const name;
	const char * const mode;
	const fp_cp_cp real_fopen;
	const i_cp_i_ real_open;
#endif
{
	LSR_MAKE_ERRNO_VAR(err);
	int fd;

	if ( real_fopen == NULL )
	{
		LSR_SET_ERRNO_MISSING();
		return NULL;
	}

	if ( mode == NULL )
	{
		LSR_SET_ERRNO (err);
		return (*real_fopen) (name, mode);
	}

	if ( ((strchr (mode, (int)'w') != NULL)
		|| (strchr (mode, (int)'W') != NULL))
		&& (real_open != NULL) )
	{
		if ( __lsr_can_wipe_filename (name, 1) != 0 )
		{
			fd = (*real_open) (name, O_WRONLY|O_EXCL);
			if ( fd >= 0 )
			{
				__lsr_fd_truncate ( fd, (off64_t)0 );
				close (fd);
			}
		}
	}

	LSR_SET_ERRNO (err);
	return (*real_fopen) (name, mode);
}

/* ======================================================= */

#ifdef HAVE_FOPEN64

# ifdef fopen64
#  undef fopen64
# endif

FILE*
fopen64 (
# ifdef LSR_ANSIC
	const char * const name, const char * const mode)
# else
	name, mode)
	const char * const name;
	const char * const mode;
# endif
{
# if (defined __GNUC__) && (!defined fopen64)
#  pragma GCC poison fopen64
# endif

	__lsr_main ();
# ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: fopen64(%s, %s)\n",
		(name==NULL)? "null" : name,
		 (mode==NULL)? "null" : mode);
	fflush (stderr);
# endif
	return generic_fopen (name, mode, __lsr_real_fopen64_location (),
		__lsr_real_open64_location ());
}
#endif /* HAVE_FOPEN64 */

/* ======================================================= */

#ifdef fopen
# undef fopen
#endif

FILE*
fopen (
#ifdef LSR_ANSIC
	const char * const name, const char * const mode)
#else
	name, mode)
	const char * const name;
	const char * const mode;
#endif
{
#if (defined __GNUC__) && (!defined fopen)
# pragma GCC poison fopen
#endif

	__lsr_main ();
#ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: fopen(%s, %s)\n",
		(name==NULL)? "null" : name,
		(mode==NULL)? "null" : mode);
	fflush (stderr);
#endif
	return generic_fopen (name, mode, __lsr_real_fopen_location (),
		__lsr_real_open_location ());
}

/* ======================================================= */

#ifndef LSR_ANSIC
static FILE* generic_freopen LSR_PARAMS((
	const char * const name, const char * const mode, FILE * stream,
	const fp_cp_cp_fp real_freopen, const i_cp_i_ real_open));
#endif

static FILE*
generic_freopen (
#ifdef LSR_ANSIC
	const char * const path, const char * const mode, FILE * stream,
	const fp_cp_cp_fp real_freopen, const i_cp_i_ real_open)
#else
	path, mode, stream, real_freopen, real_open)
	const char * const path;
	const char * const mode;
	FILE * stream;
	const fp_cp_cp_fp real_freopen;
	const i_cp_i_ real_open;
#endif
{
	LSR_MAKE_ERRNO_VAR(err);
	int fd;

	if ( real_freopen == NULL )
	{
		LSR_SET_ERRNO_MISSING();
		return NULL;
	}

	if ( (mode == NULL) || (stream == NULL) )
	{
		LSR_SET_ERRNO (err);
		return (*real_freopen) ( path, mode, stream );
	}

	if ( ((strchr (mode, (int)'w') != NULL)
		|| (strchr (mode, (int)'W') != NULL))
		&& (real_open != NULL) )
	{
		if ( __lsr_can_wipe_filename (path, 1) != 0
			/*|| (stream == stdin)
			|| (stream == stdout)
			|| (stream == stderr)*/
		)
		{
			/* truncate the NEW path, not the OLD file descriptor */
			fd = (*real_open) (path, O_WRONLY | O_EXCL);
			if ( fd >= 0 )
			{
				__lsr_fd_truncate ( fd, (off64_t)0 );
				close (fd);
			}
		}
	}

	LSR_SET_ERRNO (err);
	return (*real_freopen) ( path, mode, stream );
}

/* ======================================================= */

#ifdef HAVE_FREOPEN64

# ifdef freopen64
#  undef freopen64
# endif

FILE*
freopen64 (
# ifdef LSR_ANSIC
	const char * const name, const char * const mode, FILE * stream)
# else
	name, mode, stream)
	const char * const name;
	const char * const mode;
	FILE * stream;
# endif
{
# if (defined __GNUC__) && (!defined freopen64)
#  pragma GCC poison freopen64
# endif

	__lsr_main ();
# ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: freopen64(%s, %s, %ld)\n",
		(name==NULL)? "null" : name,
		(mode==NULL)? "null" : mode, (long int)stream);
	fflush (stderr);
# endif
	return generic_freopen (name, mode, stream, __lsr_real_freopen64_location (),
		__lsr_real_open64_location ());
}
#endif /* HAVE_FREOPEN64 */

/* ======================================================= */

#ifdef freopen
# undef freopen
#endif

FILE*
freopen (
#ifdef LSR_ANSIC
	const char * const name, const char * const mode, FILE* stream)
#else
	name, mode, stream)
	const char * const name;
	const char * const mode;
	FILE* stream;
#endif
{
#if (defined __GNUC__) && (!defined freopen)
# pragma GCC poison freopen
#endif

	__lsr_main ();
#ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: freopen(%s, %s, %ld)\n",
		(name==NULL)? "null" : name,
		(mode==NULL)? "null" : mode, (long int)stream);
	fflush (stderr);
#endif
	return generic_freopen (name, mode, stream, __lsr_real_freopen_location (),
		__lsr_real_open_location ());
}

/* ======================================================= */

#ifndef LSR_ANSIC
static int generic_open LSR_PARAMS((
	const char * const path, const int flags,
	const mode_t mode, const i_cp_i_ real_open));
#endif

static int
generic_open (
#ifdef LSR_ANSIC
	const char * const path, const int flags,
	const mode_t mode, const i_cp_i_ real_open)
#else
	path, flags, mode, real_open)
	const char * const path;
	const int flags;
	const mode_t mode;
	const i_cp_i_ real_open;
#endif
{
	LSR_MAKE_ERRNO_VAR(err);
	int fd;

	if ( real_open == NULL )
	{
		LSR_SET_ERRNO_MISSING();
		return -1;
	}

	if ( ((flags & O_TRUNC) == O_TRUNC)
/*		&& (
		((flags & O_WRONLY) == O_WRONLY) || ((flags & O_RDWR) == O_RDWR)
		   )
*/
	   )
	{
		if ( __lsr_can_wipe_filename (path, 1) != 0 )
		{
			fd = (*real_open) (path, O_WRONLY|O_EXCL);
			if ( fd >= 0 )
			{
				__lsr_fd_truncate ( fd, (off64_t)0 );
				close (fd);
			}
		}
	}

	LSR_SET_ERRNO (err);
	return (*real_open) ( path, flags, mode );
}

/* ======================================================= */

#ifdef HAVE_OPEN64

# if (defined TEST_COMPILE) && (defined WAS_LSR_ANSIC)
#  define LSR_ANSIC 1
# endif

/* 'man 2 open' gives:
    int open(const char *pathname, int flags);
    int open(const char *pathname, int flags, mode_t mode);
   'man 3p open' (POSIX) & /usr/include/fcntl.h give:
    int open(const char *path, int oflag, ...  );
 */

# ifdef open64
#  undef open64
# endif

int
open64 (
# ifdef LSR_ANSIC
	const char * const path, const int flags, ... )
# else
	va_alist )
	va_dcl /* no semicolons here! */
	/*
	path, flags )
	const char * const path;
	const int flags;*/
# endif
{
# if (defined __GNUC__) && (!defined open64)
#  pragma GCC poison open64
# endif

# if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
	va_list args;
#  ifndef LSR_ANSIC
	char * const path = NULL;
	int flags = -1;
#  endif
# endif
	LSR_MAKE_ERRNO_VAR(err);
	mode_t mode = 0666;
	int fd;

	__lsr_main ();

# if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
#  ifdef LSR_ANSIC
	va_start (args, flags);
#  else
	va_start (args); /* cppcheck-suppress preprocessorErrorDirective */
	path = va_arg (args, char * const);
	flags = va_arg (args, int);
#  endif
	if ( (flags & O_CREAT) != 0 )
	{
		mode = va_arg (args, mode_t);
	}
# endif

# ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: open64(%s, 0%o, ...)\n",
		(path==NULL)? "null" : path, flags);
	fflush (stderr);
# endif

	fd = generic_open (path, flags, mode, __lsr_real_open64_location ());
# if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
	LSR_GET_ERRNO(err);
	va_end (args);
	LSR_SET_ERRNO (err);
# endif
	return fd;
}
#endif /* HAVE_OPEN64 */

/* ======================================================= */

#ifdef open
# undef open
#endif

int
open (
#ifdef LSR_ANSIC
	const char * const path, const int flags, ... )
#else
	va_alist )
	va_dcl /* no semicolons here! */
	/*
	path, flags )
	const char * const path;
	const int flags;*/
#endif
{
#if (defined __GNUC__) && (!defined open)
# pragma GCC poison open
#endif

#if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
	va_list args;
# ifndef LSR_ANSIC
	char * const path = NULL;
	int flags = -1;
# endif
#endif
	mode_t mode = 0666;
	int fd;
	LSR_MAKE_ERRNO_VAR(err);

	__lsr_main ();
#if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
# ifdef LSR_ANSIC
	va_start (args, flags);
# else
	va_start (args);
	path = va_arg (args, char * const);
	flags = va_arg (args, int);
# endif
	if ( (flags & O_CREAT) != 0 )
	{
		mode = va_arg (args, mode_t);
	}
#endif

#ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: open(%s, 0%o, ...)\n",
		(path==NULL)? "null" : path, flags);
	fflush (stderr);
#endif

	fd = generic_open (path, flags, mode, __lsr_real_open_location ());
#if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
	LSR_GET_ERRNO(err);
	va_end (args);
	LSR_SET_ERRNO (err);
#endif
	return fd;
}

/* ======================================================= */

#ifdef TEST_COMPILE
# undef LSR_ANSIC
#endif

#ifndef LSR_ANSIC
static int generic_openat LSR_PARAMS((
	const int dirfd, const char * const path, const int flags,
	const mode_t mode, const i_i_cp_i_ real_openat));
#endif

static int
generic_openat (
#ifdef LSR_ANSIC
	const int dirfd, const char * const pathname, const int flags,
	const mode_t mode, const i_i_cp_i_ real_openat)
#else
	dirfd, pathname, flags, mode, real_openat)
	const int dirfd;
	const char * const pathname;
	const int flags;
	const mode_t mode;
	const i_i_cp_i_ real_openat;
#endif
{
	int fd;
	LSR_MAKE_ERRNO_VAR(err);

	if ( real_openat == NULL )
	{
		LSR_SET_ERRNO_MISSING();
		return -1;
	}

	if ( ((flags & O_TRUNC) == O_TRUNC)
/*		&& (
		((flags & O_WRONLY) == O_WRONLY) || ((flags & O_RDWR) == O_RDWR)
		   )
*/
	   )
	{
		if ( __lsr_can_wipe_filename_atdir (pathname, dirfd, 1) != 0 )
		{
			fd = (*real_openat) (dirfd, pathname,
				O_WRONLY|O_EXCL, S_IRUSR|S_IWUSR);
			if ( fd >= 0 )
			{
				__lsr_fd_truncate ( fd, (off64_t)0 );
				close (fd);
			}
		}
	}

	LSR_SET_ERRNO (err);
	return (*real_openat) ( dirfd, pathname, flags, mode );
}

/* ======================================================= */

#ifdef HAVE_OPENAT64

# if (defined TEST_COMPILE) && (defined WAS_LSR_ANSIC)
#  define LSR_ANSIC 1
# endif

# ifdef openat64
#  undef openat64
# endif

int
openat64 (
# ifdef LSR_ANSIC
	const int dirfd, const char * const pathname, const int flags, ...)
# else
	va_alist )
	va_dcl /* no semicolons here! */
	/*
	dirfd, pathname, flags )
	const int dirfd;
	const char * const pathname;
	const int flags;*/
# endif
{
# if (defined __GNUC__) && (!defined openat64)
#  pragma GCC poison openat64
# endif

	int ret_fd;
	mode_t mode = 0666;
# if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
	va_list args;
#  ifndef LSR_ANSIC
	int dirfd = -1;
	char * const pathname = NULL;
	int flags = -1;
#  endif
# endif
	LSR_MAKE_ERRNO_VAR(err);

	__lsr_main ();
# if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
#  ifdef LSR_ANSIC
	va_start (args, flags);
#  else
	va_start (args);
	dirfd = va_arg (args, int);
	pathname = va_arg (args, char * const);
	flags = va_arg (args, int);
#  endif
	if ( (flags & O_CREAT) != 0 )
	{
		mode = va_arg (args, mode_t);
	}
# endif
# ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: openat64(%d, %s, 0%o, ...)\n",
		dirfd, (pathname==NULL)? "null" : pathname, flags);
	fflush (stderr);
# endif

	ret_fd = generic_openat (dirfd, pathname, flags, mode,
		__lsr_real_openat64_location ());
# if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
	LSR_GET_ERRNO(err);
	va_end (args);
	LSR_SET_ERRNO (err);
# endif
	return ret_fd;
}
#endif /* HAVE_OPENAT64 */

/* ======================================================= */

/*/
int openat(int dirfd, const char *pathname, int flags);
int openat(int dirfd, const char *pathname, int flags, mode_t mode);
 */

#ifdef openat
# undef openat
#endif

int
openat (
#ifdef LSR_ANSIC
	const int dirfd, const char * const pathname, const int flags, ...)
#else
	va_alist )
	va_dcl /* no semicolons here! */
	/*
	dirfd, pathname, flags )
	const int dirfd;
	const char * const pathname;
	const int flags;*/
#endif
{
#if (defined __GNUC__) && (!defined openat)
# pragma GCC poison openat
#endif

	int ret_fd;
	mode_t mode = 0666;
#if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
	va_list args;
# ifndef LSR_ANSIC
	int dirfd = -1;
	char * const pathname = NULL;
	int flags = -1;
# endif
#endif
	LSR_MAKE_ERRNO_VAR(err);

	__lsr_main ();
#if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
# ifdef LSR_ANSIC
	va_start (args, flags);
# else
	va_start (args);
	dirfd = va_arg (args, int);
	pathname = va_arg (args, char * const);
	flags = va_arg (args, int);
# endif
	if ( (flags & O_CREAT) != 0 )
	{
		mode = va_arg (args, mode_t);
	}
#endif
#ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: openat(%d, %s, 0%o, ...)\n", dirfd,
		(pathname==NULL)? "null" : pathname, flags);
	fflush (stderr);
#endif

	ret_fd = generic_openat (dirfd, pathname, flags, mode,
		__lsr_real_openat_location ());
#if (defined HAVE_STDARG_H) || (defined HAVE_VARARGS_H)
	LSR_GET_ERRNO(err);
	va_end (args);
	LSR_SET_ERRNO (err);
#endif
	return ret_fd;
}
