/*
 * A library for secure removing files.
 *	-- file truncating functions' replacements.
 *
 * Copyright (C) 2007-2015 Bogdan Drozdowski, bogdandr (at) op.pl
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

#ifdef HAVE_SYS_STAT_H
# ifdef STAT_MACROS_BROKEN
#  if STAT_MACROS_BROKEN
#   error Stat macros broken. Change your C library.
#  endif
# endif
#endif

#ifndef _GNU_SOURCE
# define _GNU_SOURCE	1	/* need F_SETLEASE, fsync(), fallocate() */
#endif

#ifndef _XOPEN_SOURCE
# define _XOPEN_SOURCE 600	/* posix_fallocate() */
#endif

#ifdef HAVE_STRING_H
# if (!defined STDC_HEADERS) && (defined HAVE_MEMORY_H)
#  include <memory.h>
# endif
# include <string.h>
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>	/* size_t, off_t (otherwise #define'd by ./configure) */
#endif

#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif

#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#else
# define O_WRONLY	1
#endif

#ifndef O_EXCL
# define O_EXCL		0200
#endif

#include <stdio.h>

#ifdef HAVE_LINUX_FALLOC_H
# include <linux/falloc.h>
#else
# define FALLOC_FL_KEEP_SIZE 0x01
#endif

#include "libsecrm-priv.h"

/*#ifndef HAVE_UNISTD_H*/
/*
# ifndef HAVE_TRUNCATE64
extern int truncate64 LSR_PARAMS((const char * const path, const off64_t length));
# endif
# ifndef HAVE_FTRUNCATE64
extern int ftruncate64 LSR_PARAMS((int fd, const off64_t length));
# endif
*/
/*#endif*/
#ifndef HAVE_POSIX_FALLOCATE
extern int posix_fallocate LSR_PARAMS ((int fd, off_t offset, off_t len));
#endif
#ifndef HAVE_FALLOCATE
extern int fallocate LSR_PARAMS ((int fd, int mode, off_t offset, off_t len));
#endif


#ifdef __GNUC__
# ifndef fopen
#  pragma GCC poison fopen
# endif
# ifndef open
#  pragma GCC poison open
# endif
# ifndef freopen
#  pragma GCC poison freopen
# endif
# ifndef openat
#  pragma GCC poison openat
# endif
# ifndef open64
#  pragma GCC poison open64
# endif
# ifndef fopen64
#  pragma GCC poison fopen64
# endif
# ifndef freopen64
#  pragma GCC poison freopen64
# endif
# ifndef openat64
#  pragma GCC poison openat64
# endif
#endif

/* ======================================================= */

#ifdef truncate
# undef truncate
#endif

int
truncate (
#ifdef LSR_ANSIC
	const char * const path, const off_t length)
#else
	path, length)
	const char * const path;
	const off_t length;
#endif
{
#if (defined __GNUC__) && (!defined truncate)
# pragma GCC poison truncate
#endif

#ifdef HAVE_SYS_STAT_H
	struct stat s;
#endif
	FILE *f = NULL;
	int fd = -1;
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
	fprintf (stderr, "libsecrm: truncate(%s, %ld)\n", (path==NULL)? "null" : path, length);
	fflush (stderr);
#endif

	if ( __lsr_real_truncate_location () == NULL )
	{
		SET_ERRNO_MISSING();
		return -1;
	}

	if ( path == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_truncate_location ()) (path, length);
	}

	if ( path[0] == '\0' /*strlen (path) == 0*/ )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_truncate_location ()) (path, length);
	}

#ifdef HAVE_SYS_STAT_H
# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	if ( stat (path, &s) == 0 )
	{
		/* don't operate on non-files */
		if ( !S_ISREG (s.st_mode) )
		{
# ifdef HAVE_ERRNO_H
			errno = err;
# endif
			return (*__lsr_real_truncate_location ()) (path, length);
		}
	}
	else
	{
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		return (*__lsr_real_truncate_location ()) (path, length);
	}

	if ( (__lsr_check_prog_ban () != 0) || (__lsr_check_file_ban (path) != 0)
		|| (__lsr_check_file_ban_proc (path) != 0) )
	{
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		return (*__lsr_real_truncate_location ()) (path, length);
	}

	/* opening the file in exclusive mode */

# ifdef HAVE_UNISTD_H	/* need close(fd) */
	if ( __lsr_real_open_location () != NULL )
	{

#  ifdef HAVE_ERRNO_H
		errno = 0;
#  endif
		fd = (*__lsr_real_open_location ()) ( path, O_WRONLY|O_EXCL );
		if ( (fd < 0)
#  ifdef HAVE_ERRNO_H
/*			|| (errno != 0)*/
#  endif
		   )
		{
#  ifdef HAVE_UNISTD_H
/*			if ( fd >= 0 ) close (fd);*/
#  endif
#  ifdef HAVE_ERRNO_H
			errno = err;
#  endif
			return (*__lsr_real_truncate_location ()) (path, length);
		}

		if ( __lsr_set_signal_lock ( &fcntl_signal, fd, &fcntl_sig_old
#  if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
			, &sa, &old_sa, &res_sig
#  else
			, &sig_hndlr
#  endif
			) == 0
		)
		{

#  ifdef HAVE_UNISTD_H
#   if (defined HAVE_LONG_LONG) && (defined LSR_ANSIC)
			__lsr_fd_truncate ( fd, length*1LL );
#   else
			__lsr_fd_truncate ( fd, length*((off64_t) 1) );
#   endif
#  endif
			__lsr_unset_signal_unlock ( fcntl_signal, fd, fcntl_sig_old
#  if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
				, &old_sa, res_sig
#  else
				, &sig_hndlr
#  endif
				);
		}

		close (fd);
	}
	else
# endif	/* unistd.h */
	if ( __lsr_real_fopen_location () != NULL )
	{

# ifdef HAVE_ERRNO_H
		errno = 0;
# endif
		f = (*__lsr_real_fopen_location ()) ( path, "r+x" );

		if ( (f == NULL)
# ifdef HAVE_ERRNO_H
/*			|| (errno != 0)*/
# endif
		   )
		{
# ifdef HAVE_UNISTD_H
/*			if ( f != NULL ) fclose (f);*/
# endif
# ifdef HAVE_ERRNO_H
			errno = err;
# endif
			return (*__lsr_real_truncate_location ()) (path, length);
		}

# ifdef HAVE_ERRNO_H
		errno = 0;
# endif
		fd = fileno (f);
		if ( (fd < 0)
# ifdef HAVE_ERRNO_H
/*			|| (errno != 0)*/
# endif
		   )
		{
			fclose (f);
# ifdef HAVE_ERRNO_H
			errno = err;
# endif
			return (*__lsr_real_truncate_location ()) (path, length);
		}


		if ( __lsr_set_signal_lock ( &fcntl_signal, fd, &fcntl_sig_old
# if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
			, &sa, &old_sa, &res_sig
# else
			, &sig_hndlr
# endif
			) == 0
		)
		{

# ifdef HAVE_UNISTD_H
#  if (defined HAVE_LONG_LONG) && (defined LSR_ANSIC)
			__lsr_fd_truncate ( fd, length*1LL );
#  else
			__lsr_fd_truncate ( fd, length*((off64_t) 1) );
#  endif
# endif
			__lsr_unset_signal_unlock ( fcntl_signal, fd, fcntl_sig_old
# if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
				, &old_sa, res_sig
# else
				, &sig_hndlr
# endif
				);
		}

		fclose (f);
	}
	else
	{
		/* Can't open file */
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		return (*__lsr_real_truncate_location ()) (path, length);
	}
#endif		/* sys/stat.h */

#ifdef HAVE_ERRNO_H
	errno = err;
#endif
	return (*__lsr_real_truncate_location ()) (path, length);
}
/* ======================================================= */

#ifdef truncate64
# undef truncate64
#endif

int
truncate64 (
#ifdef LSR_ANSIC
	const char * const path, const off64_t length)
#else
	path, length)
	const char * const path;
	const off64_t length;
#endif
{
#if (defined __GNUC__) && (!defined truncate64)
# pragma GCC poison truncate64
#endif

#ifdef HAVE_SYS_STAT_H
	struct stat64 s;
#endif
	FILE *f = NULL;
	int fd = -1;
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
	fprintf (stderr, "libsecrm: truncate64(%s, %lld)\n", (path==NULL)? "null" : path, length);
	fflush (stderr);
#endif

	if ( __lsr_real_truncate64_location () == NULL )
	{
		SET_ERRNO_MISSING();
		return -1;
	}

	if ( path == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_truncate64_location ()) (path, length);
	}

	if ( path[0] == '\0' /*strlen (path) == 0*/ )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_truncate64_location ()) (path, length);
	}

#ifdef HAVE_SYS_STAT_H
# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	if ( stat64 (path, &s) == 0 )
	{
		/* don't operate on non-files */
		if ( !S_ISREG (s.st_mode) )
		{
# ifdef HAVE_ERRNO_H
			errno = err;
# endif
			return (*__lsr_real_truncate64_location ()) (path, length);
		}
	}
	else
	{
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		return (*__lsr_real_truncate64_location ()) (path, length);
	}

	if ( (__lsr_check_prog_ban () != 0) || (__lsr_check_file_ban (path) != 0)
		|| (__lsr_check_file_ban_proc (path) != 0) )
	{
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		return (*__lsr_real_truncate64_location ()) (path, length);
	}

# ifdef HAVE_UNISTD_H	/* need close(fd) */
	if ( __lsr_real_open64_location () != NULL )
	{

#  ifdef HAVE_ERRNO_H
		errno = 0;
#  endif
		fd = (*__lsr_real_open64_location ()) ( path, O_WRONLY|O_EXCL );
		if ( (fd < 0)
#  ifdef HAVE_ERRNO_H
/*			|| (errno != 0)*/
#  endif
		   )
		{
/*			if ( fd >= 0 ) close (fd);*/
#  ifdef HAVE_ERRNO_H
			errno = err;
#  endif
			return (*__lsr_real_truncate64_location ()) (path, length);
		}
		if ( __lsr_set_signal_lock ( &fcntl_signal, fd, &fcntl_sig_old
#  if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
			, &sa, &old_sa, &res_sig
#  else
			, &sig_hndlr
#  endif
			) == 0
		)
		{
			__lsr_fd_truncate ( fd, length );
			__lsr_unset_signal_unlock ( fcntl_signal, fd, fcntl_sig_old
#  if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
				, &old_sa, res_sig
#  else
				, &sig_hndlr
#  endif
				);
		}

		close (fd);
	}
	else
# endif		/* unistd.h */
	if ( __lsr_real_fopen64_location () != NULL )
	{
# ifdef HAVE_ERRNO_H
		errno = 0;
# endif
		f = (*__lsr_real_fopen64_location ()) ( path, "r+x" );
		if ( (f == NULL)
# ifdef HAVE_ERRNO_H
/*			|| (errno != 0)*/
# endif
		   )
		{
# ifdef HAVE_UNISTD_H
/*			if ( f != NULL ) fclose (f);*/
# endif
# ifdef HAVE_ERRNO_H
			errno = err;
# endif
			return (*__lsr_real_truncate64_location ()) (path, length);
		}
# ifdef HAVE_ERRNO_H
		errno = 0;
# endif
		fd = fileno (f);
		if ( (fd < 0)
# ifdef HAVE_ERRNO_H
/*			|| (errno != 0)*/
# endif
		   )
		{
			fclose (f);
# ifdef HAVE_ERRNO_H
			errno = err;
# endif
			return (*__lsr_real_truncate64_location ()) (path, length);
		}

		if ( __lsr_set_signal_lock ( &fcntl_signal, fd, &fcntl_sig_old
# if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
			, &sa, &old_sa, &res_sig
# else
			, &sig_hndlr
# endif
			) == 0
		)
		{

# ifdef HAVE_UNISTD_H
			__lsr_fd_truncate ( fd, length );
# endif
			__lsr_unset_signal_unlock ( fcntl_signal, fd, fcntl_sig_old
# if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
				, &old_sa, res_sig
# else
				, &sig_hndlr
# endif
				);
		}
		fclose (f);
	}
	else
	{
		/* Can't open file */
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		return (*__lsr_real_truncate64_location ()) (path, length);
	}
#endif		/* sys/stat.h */

#ifdef HAVE_ERRNO_H
	errno = err;
#endif
	return (*__lsr_real_truncate64_location ()) (path, length);
}

/* ======================================================= */

#ifdef ftruncate
# undef ftruncate
#endif

int
ftruncate (
#ifdef LSR_ANSIC
	int fd, const off_t length)
#else
	fd, length)
	int fd;
	const off_t length;
#endif
{
#if (defined __GNUC__) && (!defined ftruncate)
# pragma GCC poison ftruncate
#endif

#ifdef HAVE_SYS_STAT_H
	struct stat s;
#endif
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
	fprintf (stderr, "libsecrm: ftruncate(%d, %ld)\n", fd, length);
	fflush (stderr);
#endif

	if ( __lsr_real_ftruncate_location () == NULL )
	{
		SET_ERRNO_MISSING();
		return -1;
	}

	if ( __lsr_check_prog_ban () != 0 )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_ftruncate_location ()) (fd, length);
	}

#ifdef HAVE_SYS_STAT_H
# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	if ( fstat (fd, &s) == 0 )
	{
		/* don't operate on non-files */
		if ( !S_ISREG (s.st_mode) )
		{
# ifdef HAVE_ERRNO_H
			errno = err;
# endif
			return (*__lsr_real_ftruncate_location ()) (fd, length);
		}
	}
	else
	{
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		return (*__lsr_real_ftruncate_location ()) (fd, length);
	}

	if ( __lsr_set_signal_lock ( &fcntl_signal, fd, &fcntl_sig_old
# if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
		, &sa, &old_sa, &res_sig
# else
		, &sig_hndlr
# endif
		) == 0
	)
	{
# ifdef HAVE_UNISTD_H
#  if (defined HAVE_LONG_LONG) && (defined LSR_ANSIC)
		__lsr_fd_truncate ( fd, length*1LL );
#  else
		__lsr_fd_truncate ( fd, length*((off64_t) 1) );
#  endif
# endif

		__lsr_unset_signal_unlock ( fcntl_signal, fd, fcntl_sig_old
# if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
			, &old_sa, res_sig
# else
			, &sig_hndlr
# endif
			);
	}

#endif	/* sys/stat.h */

#ifdef HAVE_ERRNO_H
	errno = err;
#endif
	return (*__lsr_real_ftruncate_location ()) (fd, length);
}

/* ======================================================= */

#ifdef ftruncate64
# undef ftruncate64
#endif

int
ftruncate64 (
#ifdef LSR_ANSIC
	int fd, const off64_t length)
#else
	fd, length)
	int fd;
	const off64_t length;
#endif
{
#if (defined __GNUC__) && (!defined ftruncate64)
# pragma GCC poison ftruncate64
#endif

#ifdef HAVE_SYS_STAT_H
	struct stat64 s;
#endif
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
	fprintf (stderr, "libsecrm: ftruncate64(%d, %lld)\n", fd, length);
	fflush (stderr);
#endif

	if ( __lsr_real_ftruncate64_location () == NULL )
	{
		SET_ERRNO_MISSING();
		return -1;
	}

	if ( __lsr_check_prog_ban () != 0 )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_ftruncate64_location ()) (fd, length);
	}

#ifdef HAVE_SYS_STAT_H
# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	if ( fstat64 (fd, &s) == 0 )
	{
		/* don't operate on non-files */
		if ( !S_ISREG (s.st_mode) )
		{
# ifdef HAVE_ERRNO_H
			errno = err;
# endif
			return (*__lsr_real_ftruncate64_location ()) (fd, length);
		}
	}
	else
	{
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		return (*__lsr_real_ftruncate64_location ()) (fd, length);
	}

	if ( __lsr_set_signal_lock ( &fcntl_signal, fd, &fcntl_sig_old
# if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
		, &sa, &old_sa, &res_sig
# else
		, &sig_hndlr
# endif
		) == 0
	)
	{

# ifdef HAVE_UNISTD_H
		__lsr_fd_truncate ( fd, length );
# endif
		__lsr_unset_signal_unlock ( fcntl_signal, fd, fcntl_sig_old
# if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
			, &old_sa, res_sig
# else
			, &sig_hndlr
# endif
			);
	}

#endif	/* sys/stat.h */

#ifdef HAVE_ERRNO_H
	errno = err;
#endif
	return (*__lsr_real_ftruncate64_location ()) (fd, length);
}

/* ======================================================= */

#ifdef posix_fallocate
# undef posix_fallocate
#endif

int
posix_fallocate (
#ifdef LSR_ANSIC
	int fd, off_t offset, off_t len)
#else
	fd, offset, len)
	int fd;
	off_t offset;
	off_t len;
#endif
{
#if (defined __GNUC__) && (!defined posix_fallocate)
# pragma GCC poison posix_fallocate
#endif

#ifdef HAVE_SYS_STAT_H
	struct stat64 s;
#endif
#ifdef HAVE_ERRNO_H
	int err = errno; /* posix_fallocate does NOT set errno. */
#endif
	int res;

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
	fprintf (stderr, "libsecrm: posix_fallocate(%d, %lld, %lld)\n", fd, offset, len);
	fflush (stderr);
#endif

	if ( __lsr_real_posix_fallocate_location () == NULL )
	{
		SET_ERRNO_MISSING();
		return -1;
	}

	if ( __lsr_check_prog_ban () != 0 )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_posix_fallocate_location ()) (fd, offset, len);
	}

#ifdef HAVE_SYS_STAT_H
# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	if ( fstat64 (fd, &s) == 0 )
	{
		/* don't operate on non-files */
		if ( !S_ISREG (s.st_mode) )
		{
# ifdef HAVE_ERRNO_H
			errno = err;
# endif
			return (*__lsr_real_posix_fallocate_location ()) (fd, offset, len);
		}
	}
	else
	{
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		return (*__lsr_real_posix_fallocate_location ()) (fd, offset, len);
	}

# ifdef HAVE_ERRNO_H
	errno = err;
# endif
	res = (*__lsr_real_posix_fallocate_location ()) (fd, offset, len);
# ifdef HAVE_ERRNO_H
	err = errno;
# endif
	if ( (res == 0) && (offset+len > s.st_size) )
	{
		/* success and we're exceeding the current file size. */

		if ( __lsr_set_signal_lock ( &fcntl_signal, fd, &fcntl_sig_old
# if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
			, &sa, &old_sa, &res_sig
# else
			, &sig_hndlr
# endif
			) == 0
		)
		{
# ifdef HAVE_UNISTD_H
			/* truncate the file back to its original size: */
			__lsr_fd_truncate ( fd, /*offset+len -*/ s.st_size );
# endif
			__lsr_unset_signal_unlock ( fcntl_signal, fd, fcntl_sig_old
# if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
				, &old_sa, res_sig
# else
				, &sig_hndlr
# endif
				);
		}

	} /* if ( res == 0 ) */
#endif	/* sys/stat.h */

#ifdef HAVE_ERRNO_H
	errno = err;
#endif
	return res;
}

/* ======================================================= */

#ifdef fallocate
# undef fallocate
#endif

int
fallocate (
#ifdef LSR_ANSIC
	int fd, int mode, off_t offset, off_t len)
#else
	fd, mode, offset, len)
	int fd;
	int mode;
	off_t offset;
	off_t len;
#endif
{
#if (defined __GNUC__) && (!defined fallocate)
# pragma GCC poison fallocate
#endif

#ifdef HAVE_SYS_STAT_H
	struct stat64 s;
#endif
#ifdef HAVE_ERRNO_H
	int err = 0;
#endif
	int res;

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
	fprintf (stderr, "libsecrm: fallocate(%d, %lld, %lld)\n", fd, offset, len);
	fflush (stderr);
#endif

	if ( __lsr_real_fallocate_location () == NULL )
	{
		SET_ERRNO_MISSING();
		return -1;
	}

	if ( __lsr_check_prog_ban () != 0 )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_fallocate_location ()) (fd, mode, offset, len);
	}
	if ( ((mode & FALLOC_FL_KEEP_SIZE) == FALLOC_FL_KEEP_SIZE)
		&& (__lsr_real_ftruncate64_location () == NULL) )
	{
		/* we're supposed to keep the file size unchanged, but
		   we can't truncate it - leave. */
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_fallocate_location ()) (fd, mode, offset, len);
	}

#ifdef HAVE_SYS_STAT_H
# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	if ( fstat64 (fd, &s) == 0 )
	{
		/* don't operate on non-files */
		if ( !S_ISREG (s.st_mode) )
		{
# ifdef HAVE_ERRNO_H
			errno = err;
# endif
			return (*__lsr_real_fallocate_location ()) (fd, mode, offset, len);
		}
	}
	else
	{
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		return (*__lsr_real_fallocate_location ()) (fd, mode, offset, len);
	}

#ifdef HAVE_ERRNO_H
	errno = err;
#endif
	res = (*__lsr_real_fallocate_location ()) (fd, mode, offset, len);
#ifdef HAVE_ERRNO_H
	err = errno;
#endif
	if ( (res == 0) && (offset+len > s.st_size) )
	{
		/* success and we're exceeding the current file size. */

		if ( __lsr_set_signal_lock ( &fcntl_signal, fd, &fcntl_sig_old
# if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
			, &sa, &old_sa, &res_sig
# else
			, &sig_hndlr
# endif
			) == 0
		)
		{
# ifdef HAVE_UNISTD_H
			/* truncate the file back to its original size: */
			__lsr_fd_truncate ( fd, /*offset+len -*/ s.st_size );
# endif
			if ( (mode & FALLOC_FL_KEEP_SIZE) == FALLOC_FL_KEEP_SIZE )
			{
				/* we're supposed to keep the file size unchanged,
				   so truncate the file back. */
				(*__lsr_real_ftruncate64_location ()) (fd, s.st_size);
			}
			__lsr_unset_signal_unlock ( fcntl_signal, fd, fcntl_sig_old
# if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
				, &old_sa, res_sig
# else
				, &sig_hndlr
# endif
				);
		}

#endif	/* sys/stat.h */
	} /* if ( res == 0 ) */

#ifdef HAVE_ERRNO_H
	errno = err;
#endif
	return res;
}
