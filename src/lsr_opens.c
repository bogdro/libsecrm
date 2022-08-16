/*
 * A library for secure removing files.
 *	-- file opening functions' replacements.
 *
 * Copyright (C) 2007-2008 Bogdan Drozdowski, bogdandr (at) op.pl
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

#include "lsr_cfg.h"

#ifdef STAT_MACROS_BROKEN
# if STAT_MACROS_BROKEN
#  error Stat macros broken. Change your C library.
# endif
#endif

#define _LARGEFILE64_SOURCE 1
#define _ATFILE_SOURCE 1

#ifdef HAVE_STDARG_H
# include <stdarg.h>
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

#include "libsecrm-priv.h"

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
#ifndef HAVE_FOPEN64
extern FILE* fopen64 PARAMS((const char * const name, const char * const mode));
#endif
#ifndef HAVE_FREOPEN64
extern FILE* freopen64 PARAMS((const char * const path, const char * const mode, FILE * stream));
#endif
#ifndef HAVE_OPEN64
extern int open64 PARAMS((const char * const path, const int flags, ... ));
#endif
*/
/* libsecrm-priv.h:
#ifndef HAVE_OPENAT64
extern int openat64 PARAMS((const int dirfd, const char * const pathname, const int flags, ...));
#endif*/

/* ======================================================= */

#ifdef fopen64
# undef fopen64
#endif

FILE*
fopen64 (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	const char * const name, const char * const mode)
#else
	name, mode)
	const char * const name;
	const char * const mode;
#endif
{
#if (defined __GNUC__) && (!defined fopen64)
# pragma GCC poison fopen64
#endif

#ifdef HAVE_ERRNO_H
	int err = 0;
#endif
	int fd;
#ifdef HAVE_SIGNAL_H
	int res_sig;
	int fcntl_signal, fcntl_sig_old;
# if (!defined HAVE_SIGACTION) || (defined __STRICT_ANSI__)
	sighandler_t sig_hndlr;
# else
	struct sigaction sa, old_sa;
# endif
#endif

	__lsr_main ();

#ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: fopen64(%s, %s)\n", (name==NULL)? "null" : name, (mode==NULL)? "null" : mode);
	fflush (stderr);
#endif

	if ( __lsr_real_fopen64 == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = -ENOSYS;
#endif
		return NULL;
	}

	if ( (name == NULL) || (mode == NULL) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_fopen64) (name, mode);
	}

	if ( (strlen (name) == 0) || (strlen (mode) == 0) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_fopen64) (name, mode);
	}

	if ( (__lsr_check_prog_ban () != 0) || (__lsr_check_file_ban (name) != 0)
		|| (__lsr_check_file_ban_proc (name) != 0) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_fopen64) (name, mode);
	}

	if ( (strchr (mode, (int)'w') != NULL) || (strchr (mode, (int)'W') != NULL) )
	{
		if ( __lsr_real_open64 != NULL )
		{
#ifdef HAVE_ERRNO_H
			errno = 0;
#endif
			fd = (*__lsr_real_open64) (name, O_WRONLY|O_EXCL);
			if ( (fd >= 0)
#ifdef HAVE_ERRNO_H
/*				&& (errno == 0)*/
#endif
			   )
			{
				if ( __lsr_set_signal_lock ( &fcntl_signal, fd, &fcntl_sig_old
#if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
					, &sa, &old_sa, &res_sig
#else
					, &sig_hndlr
#endif
					) == 0
				)
				{
#ifdef HAVE_UNISTD_H
# if (defined HAVE_LONG_LONG) && ( \
	defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)	\
	)
					__lsr_fd_truncate ( fd, 0LL );
# else
					__lsr_fd_truncate ( fd, (off64_t)0 );
# endif
#endif
					__lsr_unset_signal_unlock ( fcntl_signal, fd, fcntl_sig_old
#if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
						, &old_sa, res_sig
#else
						, &sig_hndlr
#endif
						);
				}

			/*
#  ifdef HAVE_LONG_LONG
				ftruncate64 (fd, 0LL);
#  else
				ftruncate64 (fd, 0);
#  endif                */
				close (fd);
			}
		}
/*# ifdef HAVE_LONG_LONG
		truncate64 (name, 0LL);
# else
		truncate64 (name, 0);
# endif*/
	}

#ifdef HAVE_ERRNO_H
	errno = err;
#endif
	return (*__lsr_real_fopen64) (name, mode);
}

/* ======================================================= */

#ifdef fopen
# undef fopen
#endif

FILE*
fopen (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
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

#ifdef HAVE_ERRNO_H
	int err = 0;
#endif
	int fd;

#ifdef HAVE_SIGNAL_H
	int res_sig;
	int fcntl_signal, fcntl_sig_old;
# if (!defined HAVE_SIGACTION) || (defined __STRICT_ANSI__)
	sighandler_t sig_hndlr;
# else
	struct sigaction sa, old_sa;
# endif
#endif
	__lsr_main ();

#ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: fopen(%s, %s)\n", (name==NULL)? "null" : name, (mode==NULL)? "null" : mode);
	fflush (stderr);
#endif

	if ( __lsr_real_fopen == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = -ENOSYS;
#endif
		return NULL;
	}

	if ( (name == NULL) || (mode == NULL) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_fopen) (name, mode);
	}

	if ( (strlen (name) == 0) || (strlen (mode) == 0) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_fopen) (name, mode);
	}

	if ( (__lsr_check_prog_ban () != 0) || (__lsr_check_file_ban (name) != 0)
		|| (__lsr_check_file_ban_proc (name) != 0) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_fopen) (name, mode);
	}

	if ( (strchr (mode, (int)'w') != NULL) || (strchr (mode, (int)'W') != NULL) )
	{
		if ( __lsr_real_open != NULL )
		{
#ifdef HAVE_ERRNO_H
			errno = 0;
#endif
			fd = (*__lsr_real_open) (name, O_WRONLY|O_EXCL);
			if ( (fd >= 0)
#ifdef HAVE_ERRNO_H
/*				&& (errno == 0)*/
#endif
			   )
			{
				if ( __lsr_set_signal_lock ( &fcntl_signal, fd, &fcntl_sig_old
#if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
					, &sa, &old_sa, &res_sig
#else
					, &sig_hndlr
#endif
					) == 0
				)
				{
#ifdef HAVE_UNISTD_H
# if (defined HAVE_LONG_LONG) && ( \
	defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)	\
	)
					__lsr_fd_truncate ( fd, 0LL );
# else
					__lsr_fd_truncate ( fd, (off64_t)0 );
# endif
#endif
					__lsr_unset_signal_unlock ( fcntl_signal, fd, fcntl_sig_old
#if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
						, &old_sa, res_sig
#else
						, &sig_hndlr
#endif
						);
				}

			/*
				ftruncate (fd, 0);
			*/
				close (fd);
			}
		}
/*		truncate (name, 0);*/
	}

#ifdef HAVE_ERRNO_H
	errno = err;
#endif
	return (*__lsr_real_fopen) (name, mode);
}
/* ======================================================= */

#ifdef freopen64
# undef freopen64
#endif

FILE*
freopen64 (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	const char * const path, const char * const mode, FILE * stream)
#else
	path, mode, stream)
	const char * const path;
	const char * const mode;
	FILE * stream;
#endif
{
#if (defined __GNUC__) && (!defined freopen64)
# pragma GCC poison freopen64
#endif

#ifdef HAVE_ERRNO_H
	int err = 0;
#endif
	int fd;

#ifdef HAVE_SIGNAL_H
	int res_sig;
	int fcntl_signal, fcntl_sig_old;
# if (!defined HAVE_SIGACTION) || (defined __STRICT_ANSI__)
	sighandler_t sig_hndlr;
# else
	struct sigaction sa, old_sa;
# endif
#endif

	__lsr_main ();
#ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: freopen64(%s, %s, %ld)\n",
		(path==NULL)? "null" : path, (mode==NULL)? "null" : mode, (long)stream);
	fflush (stderr);
#endif

	if ( __lsr_real_freopen64 == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = -ENOSYS;
#endif
		return NULL;
	}

	if ( (path == NULL) || (mode == NULL) || (stream == NULL) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_freopen64) ( path, mode, stream );
	}

	if ( (strlen (path) == 0) || (strlen (mode) == 0) || (stream == stdin)
		|| (stream == stdout) || (stream == stderr)
	   )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_freopen64) ( path, mode, stream );
	}

	if ( (__lsr_check_prog_ban () != 0) || (__lsr_check_file_ban (path) != 0)
		|| (__lsr_check_file_ban_proc (path) != 0) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_freopen64) ( path, mode, stream );
	}

	if ( (strchr (mode, (int)'w') != NULL) || (strchr (mode, (int)'W') != NULL) )
	{
#ifdef HAVE_ERRNO_H
		errno = 0;
#endif
		fd = fileno (stream);
		if ( (fd < 0)
#ifdef HAVE_ERRNO_H
/*			|| (errno != 0)*/
#endif
		   )
		{
			fflush (stream);
			rewind (stream);
			if ( __lsr_real_open64 != NULL )
			{
#ifdef HAVE_ERRNO_H
				errno = 0;
#endif
				fd = (*__lsr_real_open64) (path, O_WRONLY|O_EXCL);
				if ( (fd >= 0)
#ifdef HAVE_ERRNO_H
/*					&& (errno == 0)*/
#endif
				   )
				{
					if ( __lsr_set_signal_lock ( &fcntl_signal, fd, &fcntl_sig_old
#if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
						, &sa, &old_sa, &res_sig
#else
						, &sig_hndlr
#endif
						) == 0
					)
					{
#ifdef HAVE_UNISTD_H
# if (defined HAVE_LONG_LONG) && ( \
	defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)	\
	)
						__lsr_fd_truncate ( fd, 0LL );
# else
						__lsr_fd_truncate ( fd, (off64_t)0 );
# endif
#endif
						__lsr_unset_signal_unlock ( fcntl_signal, fd, fcntl_sig_old
#if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
							, &old_sa, res_sig
#else
							, &sig_hndlr
#endif
							);
					}

				/*
#  ifdef HAVE_LONG_LONG
					ftruncate64 (fd, 0LL);
#  else
					ftruncate64 (fd, 0);
#  endif                        */
					close (fd);
				}
			}
/*# ifdef HAVE_LONG_LONG
			truncate64 (path, 0LL);
# else
			truncate64 (path, 0);
# endif*/
		}
		else
		{
			fflush (stream);
			rewind (stream);
			if ( __lsr_set_signal_lock ( &fcntl_signal, fd, &fcntl_sig_old
#if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
				, &sa, &old_sa, &res_sig
#else
				, &sig_hndlr
#endif
				) == 0
			)
			{
#ifdef HAVE_UNISTD_H
# if (defined HAVE_LONG_LONG) && ( \
	defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)	\
	)
				__lsr_fd_truncate ( fd, 0LL );
# else
				__lsr_fd_truncate ( fd, (off64_t)0 );
# endif
#endif
				__lsr_unset_signal_unlock ( fcntl_signal, fd, fcntl_sig_old
#if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
					, &old_sa, res_sig
#else
					, &sig_hndlr
#endif
					);
			}

			/*
#  ifdef HAVE_LONG_LONG
			ftruncate64 (fd, 0LL);
#  else
			ftruncate64 (fd, 0);
#  endif*/
		}
/*# ifdef HAVE_LONG_LONG
			ftruncate64 (fd, 0LL);
# else
			ftruncate64 (fd, 0);
		}
# endif*/
	}

#ifdef HAVE_ERRNO_H
	errno = err;
#endif
	return (*__lsr_real_freopen64) ( path, mode, stream );
}

/* ======================================================= */

#ifdef freopen
# undef freopen
#endif

FILE*
freopen (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
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

#ifdef HAVE_ERRNO_H
	int err = 0;
#endif
	int fd;

#ifdef HAVE_SIGNAL_H
	int res_sig;
	int fcntl_signal, fcntl_sig_old;
# if (!defined HAVE_SIGACTION) || (defined __STRICT_ANSI__)
	sighandler_t sig_hndlr;
# else
	struct sigaction sa, old_sa;
# endif
#endif

	__lsr_main ();
#ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: freopen(%s, %s, %ld)\n",
		(name==NULL)? "null" : name, (mode==NULL)? "null" : mode, (long)stream);
	fflush (stderr);
#endif

	if ( __lsr_real_freopen == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = -ENOSYS;
#endif
		return NULL;
	}

	if ( (name == NULL) || (mode == NULL) || (stream == NULL) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_freopen) ( name, mode, stream );
	}

	if ( (strlen (name) == 0) || (strlen (mode) == 0) || (stream == stdin)
		|| (stream == stdout) || (stream == stderr)
	   )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_freopen) ( name, mode, stream );
	}

	if ( (__lsr_check_prog_ban () != 0) || (__lsr_check_file_ban (name) != 0)
		|| (__lsr_check_file_ban_proc (name) != 0) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_freopen) ( name, mode, stream );
	}

	if ( (strchr (mode, (int)'w') != NULL) || (strchr (mode, (int)'W') != NULL) )
	{
#ifdef HAVE_ERRNO_H
		errno = 0;
#endif
		fd = fileno (stream);
		if ( (fd < 0)
#ifdef HAVE_ERRNO_H
/*			|| (errno != 0)*/
#endif
		   )
		{
			/* problem - truncate the path, not the file descriptor */
			fflush (stream);
			rewind (stream);
			if ( __lsr_real_open != NULL )
			{
#ifdef HAVE_ERRNO_H
				errno = 0;
#endif
				fd = (*__lsr_real_open) (name, O_WRONLY|O_EXCL);
				if ( (fd >= 0)
#ifdef HAVE_ERRNO_H
/*					&& (errno == 0)*/
#endif
				   )
				{
					if ( __lsr_set_signal_lock ( &fcntl_signal, fd, &fcntl_sig_old
#if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
						, &sa, &old_sa, &res_sig
#else
						, &sig_hndlr
#endif
						) == 0
					)
					{
#ifdef HAVE_UNISTD_H
# if (defined HAVE_LONG_LONG) && ( \
	defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)	\
	)
						__lsr_fd_truncate ( fd, 0LL );
# else
						__lsr_fd_truncate ( fd, (off64_t)0 );
# endif
#endif
						__lsr_unset_signal_unlock ( fcntl_signal, fd, fcntl_sig_old
#if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
							, &old_sa, res_sig
#else
							, &sig_hndlr
#endif
						);
					}

				/*
					ftruncate (fd, 0);
				*/
					close (fd);
				}
			}
/*			truncate (path, 0);*/
		}
		else
		{
			fflush (stream);
			rewind (stream);
			if ( __lsr_set_signal_lock ( &fcntl_signal, fd, &fcntl_sig_old
#if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
				, &sa, &old_sa, &res_sig
#else
				, &sig_hndlr
#endif
				) == 0
			)
			{
#ifdef HAVE_UNISTD_H
# if (defined HAVE_LONG_LONG) && ( \
	defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)	\
	)
				__lsr_fd_truncate ( fd, 0LL );
# else
				__lsr_fd_truncate ( fd, (off64_t)0 );
# endif
#endif
				__lsr_unset_signal_unlock ( fcntl_signal, fd, fcntl_sig_old
#if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
					, &old_sa, res_sig
#else
					, &sig_hndlr
#endif
					);
			}

/*			ftruncate (fd, 0);*/
		}
	}

#ifdef HAVE_ERRNO_H
	errno = err;
#endif
	return (*__lsr_real_freopen) ( name, mode, stream );
}

/* ======================================================= */

/* 'man 2 open' gives:
    int open(const char *pathname, int flags);
    int open(const char *pathname, int flags, mode_t mode);
   'man 3p open' (POSIX) & /usr/include/fcntl.h give:
    int open(const char *path, int oflag, ...  );
 */

#ifdef open64
# undef open64
#endif

int
open64 (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	const char * const path, const int flags, ... )
#else
	path, flags, ... )
	const char * const path;
	const int flags;
#endif
{
#if (defined __GNUC__) && (!defined open64)
# pragma GCC poison open64
#endif

	va_list args;
	int ret_fd;
	mode_t mode;
#ifdef HAVE_ERRNO_H
	int err = 0;
#endif
	int fd;

#ifdef HAVE_SIGNAL_H
	int res_sig;
	int fcntl_signal, fcntl_sig_old;
# if (!defined HAVE_SIGACTION) || (defined __STRICT_ANSI__)
	sighandler_t sig_hndlr;
# else
	struct sigaction sa, old_sa;
# endif
#endif

	__lsr_main ();
#ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: open64(%s, 0%o, ...)\n", (path==NULL)? "null" : path, flags);
	fflush (stderr);
#endif

	if ( __lsr_real_open64 == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = -ENOSYS;
#endif
		return -1;
	}

	va_start (args, flags);
	mode = va_arg (args, mode_t);

	if ( path == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		ret_fd = (*__lsr_real_open64) ( path, flags, mode );
#ifdef HAVE_ERRNO_H
		err = errno;
#endif
		va_end (args);
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return ret_fd;
	}

	if ( strlen (path) == 0 )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		ret_fd = (*__lsr_real_open64) ( path, flags, mode );
#ifdef HAVE_ERRNO_H
		err = errno;
#endif
		va_end (args);
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return ret_fd;
	}

	if ( strstr (path, "rpm-tmp.") != NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		ret_fd = (*__lsr_real_open64) ( path, flags, mode );
#ifdef HAVE_ERRNO_H
		err = errno;
#endif
		va_end (args);
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return ret_fd;
	}

	if ( (__lsr_check_prog_ban () != 0) || (__lsr_check_file_ban (path) != 0)
		|| (__lsr_check_file_ban_proc (path) != 0) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		ret_fd = (*__lsr_real_open64) ( path, flags, mode );
#ifdef HAVE_ERRNO_H
		err = errno;
#endif
		va_end (args);
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return ret_fd;
	}

	if ( ((flags & O_TRUNC) == O_TRUNC)
/*		&& (
		((flags & O_WRONLY) == O_WRONLY) || ((flags & O_RDWR) == O_RDWR)
		   )
*/
	   )
	{
#ifdef HAVE_ERRNO_H
		errno = 0;
#endif
		fd = (*__lsr_real_open64) (path, O_WRONLY|O_EXCL);
		if ( (fd >= 0)
#ifdef HAVE_ERRNO_H
/*			&& (errno == 0)*/
#endif
		   )
		{
			if ( __lsr_set_signal_lock ( &fcntl_signal, fd, &fcntl_sig_old
#if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
				, &sa, &old_sa, &res_sig
#else
				, &sig_hndlr
#endif
				) == 0
			)
			{
#ifdef HAVE_UNISTD_H
# if (defined HAVE_LONG_LONG) && ( \
	defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)	\
	)
				__lsr_fd_truncate ( fd, 0LL );
# else
				__lsr_fd_truncate ( fd, (off64_t)0 );
# endif
#endif
				__lsr_unset_signal_unlock ( fcntl_signal, fd, fcntl_sig_old
#if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
					, &old_sa, res_sig
#else
					, &sig_hndlr
#endif
					);
			}

		/*
#  ifdef HAVE_LONG_LONG
			ftruncate64 (fd, 0LL);
#  else
			ftruncate64 (fd, 0);
#  endif*/
			close (fd);
		}
/*# ifdef HAVE_LONG_LONG
		truncate64 (path, 0LL);
# else
		truncate64 (path, 0);
# endif*/
	}

#ifdef HAVE_ERRNO_H
	errno = err;
#endif
	ret_fd = (*__lsr_real_open64) ( path, flags, mode );
#ifdef HAVE_ERRNO_H
	err = errno;
#endif
	va_end (args);
#ifdef HAVE_ERRNO_H
	errno = err;
#endif

	return ret_fd;
}

/* ======================================================= */

#ifdef open
# undef open
#endif

int
open (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	const char * const name, const int flags, ... )
#else
	name, flags, ... )
	const char * const name;
	const int flags;
#endif
{
#if (defined __GNUC__) && (!defined open)
# pragma GCC poison open
#endif

	va_list args;
	int ret_fd;
	mode_t mode;
	int fd;
#ifdef HAVE_ERRNO_H
	int err = 0;
#endif

#ifdef HAVE_SIGNAL_H
	int res_sig;
	int fcntl_signal, fcntl_sig_old;
# if (!defined HAVE_SIGACTION) || (defined __STRICT_ANSI__)
	sighandler_t sig_hndlr;
# else
	struct sigaction sa, old_sa;
# endif
#endif

	__lsr_main ();
#ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: open(%s, 0%o, ...)\n", (name==NULL)? "null" : name, flags);
	fflush (stderr);
#endif

	if ( __lsr_real_open == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = -ENOSYS;
#endif
		return -1;
	}

	va_start (args, flags);
	mode = va_arg (args, mode_t);

	if ( name == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		ret_fd = (*__lsr_real_open) ( name, flags, mode );
#ifdef HAVE_ERRNO_H
		err = errno;
#endif
		va_end (args);
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return ret_fd;
	}

	if ( strlen (name) == 0 )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		ret_fd = (*__lsr_real_open) ( name, flags, mode );
#ifdef HAVE_ERRNO_H
		err = errno;
#endif
		va_end (args);
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return ret_fd;
	}

	if ( strstr (name, "rpm-tmp.") != NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		ret_fd = (*__lsr_real_open) ( name, flags, mode );
#ifdef HAVE_ERRNO_H
		err = errno;
#endif
		va_end (args);
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return ret_fd;
	}

	if ( (__lsr_check_prog_ban () != 0) || (__lsr_check_file_ban (name) != 0)
		|| (__lsr_check_file_ban_proc (name) != 0) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		ret_fd = (*__lsr_real_open) ( name, flags, mode );
#ifdef HAVE_ERRNO_H
		err = errno;
#endif
		va_end (args);
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return ret_fd;
	}

	if ( ((flags & O_TRUNC) == O_TRUNC)
/*		&& (
		((flags & O_WRONLY) == O_WRONLY) || ((flags & O_RDWR) == O_RDWR)
		   )
*/
	   )
	{
#ifdef HAVE_ERRNO_H
		errno = 0;
#endif
		fd = (*__lsr_real_open) (name, O_WRONLY|O_EXCL);
		if ( (fd >= 0)
#ifdef HAVE_ERRNO_H
/*			&& (errno == 0)*/
#endif
		   )
		{
			if ( __lsr_set_signal_lock ( &fcntl_signal, fd, &fcntl_sig_old
#if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
				, &sa, &old_sa, &res_sig
#else
				, &sig_hndlr
#endif
				) == 0
			)
			{
#ifdef HAVE_UNISTD_H
# if (defined HAVE_LONG_LONG) && ( \
	defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)	\
	)
				__lsr_fd_truncate ( fd, 0LL );
# else
				__lsr_fd_truncate ( fd, (off64_t)0 );
# endif
#endif
				__lsr_unset_signal_unlock ( fcntl_signal, fd, fcntl_sig_old
#if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
					, &old_sa, res_sig
#else
					, &sig_hndlr
#endif
					);
			}

		/*
			ftruncate (fd, 0);
		*/
			close (fd);
		}
/*		truncate (path, 0);*/
	}

#ifdef HAVE_ERRNO_H
	errno = err;
#endif
	ret_fd = (*__lsr_real_open) ( name, flags, mode );
#ifdef HAVE_ERRNO_H
	err = errno;
#endif
	va_end (args);
#ifdef HAVE_ERRNO_H
	errno = err;
#endif

	return ret_fd;
}

/* ======================================================= */

#ifdef openat64
# undef openat64
#endif

int
openat64 (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	const int dirfd, const char * const pathname, const int flags, ...)
#else
	dirfd, pathname, flags, ...)
	const int dirfd;
	const char * const pathname;
	const int flags;
#endif
{
#if (defined __GNUC__) && (!defined openat64)
# pragma GCC poison openat64
#endif

	int fd;
	int ret_fd;
	mode_t mode;
	va_list args;
#ifdef HAVE_ERRNO_H
	int err = 0;
#endif

#ifdef HAVE_SIGNAL_H
	int res_sig;
	int fcntl_signal, fcntl_sig_old;
# if (!defined HAVE_SIGACTION) || (defined __STRICT_ANSI__)
	sighandler_t sig_hndlr;
# else
	struct sigaction sa, old_sa;
# endif
#endif

	__lsr_main ();

#ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: openat64(%d, %s, 0%o, ...)\n",
		dirfd, (pathname==NULL)? "null" : pathname, flags);
	fflush (stderr);
#endif

	if ( __lsr_real_openat64 == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = -ENOSYS;
#endif
		return -1;
	}

	va_start (args, flags);
	mode = va_arg (args, mode_t);

	if ( pathname == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		ret_fd = (*__lsr_real_openat64) ( dirfd, pathname, flags, mode );
#ifdef HAVE_ERRNO_H
		err = errno;
#endif
		va_end (args);
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return ret_fd;
	}

	if ( strlen (pathname) == 0 )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		ret_fd = (*__lsr_real_openat64) ( dirfd, pathname, flags, mode );
#ifdef HAVE_ERRNO_H
		err = errno;
#endif
		va_end (args);
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return ret_fd;
	}

	if ( (__lsr_check_prog_ban () != 0) || (__lsr_check_file_ban (pathname) != 0)
		|| (__lsr_check_file_ban_proc (pathname) != 0) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		ret_fd = (*__lsr_real_openat64) ( dirfd, pathname, flags, mode );
#ifdef HAVE_ERRNO_H
		err = errno;
#endif
		va_end (args);
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return ret_fd;
	}

	if ( ((flags & O_TRUNC) == O_TRUNC)
/*		&& (
		((flags & O_WRONLY) == O_WRONLY) || ((flags & O_RDWR) == O_RDWR)
		   )
*/
	   )
	{

#ifdef HAVE_ERRNO_H
		errno = 0;
#endif
		fd = (*__lsr_real_openat64) (dirfd, pathname, O_WRONLY|O_EXCL, S_IRUSR|S_IWUSR);
		if ( (fd >= 0)
#ifdef HAVE_ERRNO_H
/*			&& (errno == 0)*/
#endif
		   )
		{
			if ( __lsr_set_signal_lock ( &fcntl_signal, fd, &fcntl_sig_old
#if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
				, &sa, &old_sa, &res_sig
#else
				, &sig_hndlr
#endif
				) == 0
			)
			{
#ifdef HAVE_UNISTD_H
# if (defined HAVE_LONG_LONG) && ( \
	defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)	\
	)
				__lsr_fd_truncate ( fd, 0LL );
# else
				__lsr_fd_truncate ( fd, (off64_t)0 );
# endif
#endif
				__lsr_unset_signal_unlock ( fcntl_signal, fd, fcntl_sig_old
#if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
					, &old_sa, res_sig
#else
					, &sig_hndlr
#endif
					);
			}

		/*
#  ifdef HAVE_LONG_LONG
			ftruncate64 (fd, 0LL);
#  else
			ftruncate64 (fd, 0);
#  endif        */
			close (fd);
		}
	}
#ifdef HAVE_ERRNO_H
	errno = err;
#endif
	ret_fd = (*__lsr_real_openat64) ( dirfd, pathname, flags, mode );
#ifdef HAVE_ERRNO_H
	err = errno;
#endif
	va_end (args);
#ifdef HAVE_ERRNO_H
	errno = err;
#endif

	return ret_fd;
}


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
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	const int dirfd, const char * const pathname, const int flags, ...)
#else
	dirfd, pathname, flags, ...)
	const int dirfd;
	const char * const pathname;
	const int flags;
#endif
{
#if (defined __GNUC__) && (!defined openat)
# pragma GCC poison openat
#endif

	int fd;
	int ret_fd;
	mode_t mode;
	va_list args;
#ifdef HAVE_ERRNO_H
	int err = 0;
#endif

#ifdef HAVE_SIGNAL_H
	int res_sig;
	int fcntl_signal, fcntl_sig_old;
# if (!defined HAVE_SIGACTION) || (defined __STRICT_ANSI__)
	sighandler_t sig_hndlr;
# else
	struct sigaction sa, old_sa;
# endif
#endif

	__lsr_main ();

#ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: openat(%d, %s, 0%o, ...)\n", dirfd,
		(pathname==NULL)? "null" : pathname, flags);
	fflush (stderr);
#endif

	if ( __lsr_real_openat == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = -ENOSYS;
#endif
		return -1;
	}

	va_start (args, flags);
	mode = va_arg (args, mode_t);

	if ( pathname == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		ret_fd = (*__lsr_real_openat) ( dirfd, pathname, flags, mode );
#ifdef HAVE_ERRNO_H
		err = errno;
#endif
		va_end (args);
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return ret_fd;
	}

	if ( strlen (pathname) == 0 )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		ret_fd = (*__lsr_real_openat) ( dirfd, pathname, flags, mode );
#ifdef HAVE_ERRNO_H
		err = errno;
#endif
		va_end (args);
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return ret_fd;
	}

	if ( (__lsr_check_prog_ban () != 0) || (__lsr_check_file_ban (pathname) != 0)
		|| (__lsr_check_file_ban_proc (pathname) != 0) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		ret_fd = (*__lsr_real_openat) ( dirfd, pathname, flags, mode );
#ifdef HAVE_ERRNO_H
		err = errno;
#endif
		va_end (args);
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return ret_fd;
	}

	if ( ((flags & O_TRUNC) == O_TRUNC)
/*		&& (
		((flags & O_WRONLY) == O_WRONLY) || ((flags & O_RDWR) == O_RDWR)
		   )
*/
	   )
	{

#ifdef HAVE_ERRNO_H
		errno = 0;
#endif
		fd = (*__lsr_real_openat) (dirfd, pathname, O_WRONLY|O_EXCL, S_IRUSR|S_IWUSR);
		if ( (fd >= 0)
#ifdef HAVE_ERRNO_H
/*			&& (errno == 0)*/
#endif
		   )
		{
			if ( __lsr_set_signal_lock ( &fcntl_signal, fd, &fcntl_sig_old
#if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
				, &sa, &old_sa, &res_sig
#else
				, &sig_hndlr
#endif
				) == 0
			)
			{
#ifdef HAVE_UNISTD_H
# if (defined HAVE_LONG_LONG) && ( \
	defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)	\
	)
				__lsr_fd_truncate ( fd, 0LL );
# else
				__lsr_fd_truncate ( fd, (off64_t)0 );
# endif
#endif
				__lsr_unset_signal_unlock ( fcntl_signal, fd, fcntl_sig_old
#if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
					, &old_sa, res_sig
#else
					, &sig_hndlr
#endif
					);
			}

		/*
			ftruncate (fd, 0);
		*/
			close (fd);
		}
	}
#ifdef HAVE_ERRNO_H
	errno = err;
#endif
	ret_fd = (*__lsr_real_openat) ( dirfd, pathname, flags, mode );
#ifdef HAVE_ERRNO_H
	err = errno;
#endif
	va_end (args);
#ifdef HAVE_ERRNO_H
	errno = err;
#endif

	return ret_fd;
}
