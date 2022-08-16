/*
 * A library for secure removing files.
 *	-- file creation functions' replacements.
 *
 * Copyright (C) 2007-2009 Bogdan Drozdowski, bogdandr (at) op.pl
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

#define _LARGEFILE64_SOURCE 1

#ifdef HAVE_SYS_STAT_H
# ifdef STAT_MACROS_BROKEN
#  if STAT_MACROS_BROKEN
#   error Stat macros broken. Change your C library.
#  endif
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

#include "libsecrm-priv.h"

/*
#ifndef HAVE_CREAT64
extern int creat64 PARAMS((const char * const path, const mode_t mode));
#endif
*/

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

/* ======================================================= */

#ifdef creat64
# undef creat64
#endif

int
creat64 (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	const char * const path, const mode_t mode)
#else
	path, mode)
	const char * const path;
	const mode_t mode;
#endif
{
#if (defined __GNUC__) && (!defined creat64)
# pragma GCC poison creat64
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
	fprintf (stderr, "libsecrm: creat64(%s, 0%o)\n", (path==NULL)? "null" : path, mode);
	fflush (stderr);
#endif

	if ( __lsr_real_creat64_location () == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = -ENOSYS;
#endif
		return -1;
	}

	if ( path == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_creat64_location ()) ( path, mode );
	}

	if ( strlen (path) == 0 )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_creat64_location ()) ( path, mode );
	}

	if ( (__lsr_check_prog_ban () != 0) || (__lsr_check_file_ban (path) != 0)
		|| (__lsr_check_file_ban_proc (path) != 0) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_creat64_location ()) ( path, mode );
	}

	if ( __lsr_real_open64_location () != NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = 0;
#endif
		fd = (*__lsr_real_open64_location ()) (path, O_WRONLY|O_EXCL);
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
#ifdef HAVE_LONG_LONG
			ftruncate64 (fd, 0LL);
#else
			ftruncate64 (fd, 0);
#endif        */
			close (fd);
		}
	}

#ifdef HAVE_ERRNO_H
	errno = err;
#endif
	return (*__lsr_real_creat64_location ()) ( path, mode );
}

/* ======================================================= */

#ifdef creat
# undef creat
#endif

int
creat (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	const char * const path, const mode_t mode )
#else
	path, mode )
	const char * const path;
	const mode_t mode;
#endif
{
#if (defined __GNUC__) && (!defined creat)
# pragma GCC poison creat
#endif

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
	fprintf (stderr, "libsecrm: creat(%s, 0%o)\n", (path==NULL)? "null" : path, mode);
	fflush (stderr);
#endif

	if ( __lsr_real_creat_location () == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = -ENOSYS;
#endif
		return -1;
	}

	if ( path == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_creat_location ()) ( path, mode );
	}

	if ( strlen (path) == 0 )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_creat_location ()) ( path, mode );
	}

	if ( (__lsr_check_prog_ban () != 0) || (__lsr_check_file_ban (path) != 0)
		|| (__lsr_check_file_ban_proc (path) != 0) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_creat_location ()) ( path, mode );
	}

	if ( __lsr_real_open_location () != NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = 0;
#endif
		fd = (*__lsr_real_open_location ()) (path, O_WRONLY|O_EXCL);
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
	return (*__lsr_real_creat_location ()) ( path, mode );
}
