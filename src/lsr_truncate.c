/*
 * A library for secure removing files.
 *	-- file truncating functions' replacements.
 *
 * Copyright (C) 2007-2017 Bogdan Drozdowski, bogdandr (at) op.pl
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

#include "lsr_priv.h"

/*#ifndef HAVE_UNISTD_H*/
/*
# ifndef HAVE_TRUNCATE64
#  ifdef __cplusplus
extern "C" {
#  endif

extern int truncate64 LSR_PARAMS((const char * const path, const off64_t length));

#  ifdef __cplusplus
}
#  endif

# endif

# ifndef HAVE_FTRUNCATE64
#  ifdef __cplusplus
extern "C" {
#  endif

extern int ftruncate64 LSR_PARAMS((int fd, const off64_t length));

#  ifdef __cplusplus
}
#  endif

# endif
*/
/*#endif*/

#ifndef HAVE_POSIX_FALLOCATE
# ifdef __cplusplus
extern "C" {
# endif

extern int posix_fallocate LSR_PARAMS ((int fd, off_t offset, off_t len));

# ifdef __cplusplus
}
# endif

#endif

#ifndef HAVE_FALLOCATE
# ifdef __cplusplus
extern "C" {
# endif

extern int fallocate LSR_PARAMS ((int fd, int mode, off_t offset, off_t len));

# ifdef __cplusplus
}
# endif

#endif

#if (defined HAVE_SYS_STAT_H) && (! defined HAVE_FSTAT64) && (defined HAVE_FSTAT)
# define fstat64	fstat
# define stat64		stat
# define HAVE_FSTAT64	1
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
	FILE *f = NULL;
	int fd = -1;
	LSR_MAKE_ERRNO_VAR(err);

	__lsr_main ();
#ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: truncate(%s, %ld)\n",
		(path==NULL)? "null" : path, length);
	fflush (stderr);
#endif

	if ( __lsr_real_truncate_location () == NULL )
	{
		LSR_SET_ERRNO_MISSING();
		return -1;
	}

	if ( __lsr_can_wipe_filename (path) == 0 )
	{
		LSR_SET_ERRNO (err);
		return (*__lsr_real_truncate_location ()) (path, length);
	}

	/* opening the file in exclusive mode */
# ifdef HAVE_UNISTD_H	/* need close(fd) */
	if ( __lsr_real_open_location () != NULL )
	{
		fd = (*__lsr_real_open_location ()) ( path, O_WRONLY|O_EXCL );
		if ( fd < 0 )
		{
			LSR_SET_ERRNO (err);
			return (*__lsr_real_truncate_location ()) (path, length);
		}

		__lsr_fd_truncate ( fd, length*((off64_t) 1) );
		close (fd);
	}
	else
# endif	/* unistd.h */
	if ( __lsr_real_fopen_location () != NULL )
	{
		f = (*__lsr_real_fopen_location ()) ( path, "r+x" );

		if ( f == NULL )
		{
			LSR_SET_ERRNO (err);
			return (*__lsr_real_truncate_location ()) (path, length);
		}

		fd = fileno (f);
		if ( fd < 0 )
		{
			fclose (f);
			LSR_SET_ERRNO (err);
			return (*__lsr_real_truncate_location ()) (path, length);
		}

		__lsr_fd_truncate ( fd, length*((off64_t) 1) );
		fclose (f);
	}
	else
	{
		/* Can't open file */
		LSR_SET_ERRNO (err);
		return (*__lsr_real_truncate_location ()) (path, length);
	}

	LSR_SET_ERRNO (err);
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
	FILE *f = NULL;
	int fd = -1;
	LSR_MAKE_ERRNO_VAR(err);

	__lsr_main ();
#ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: truncate64(%s, %lld)\n",
		(path==NULL)? "null" : path, length);
	fflush (stderr);
#endif

	if ( __lsr_real_truncate64_location () == NULL )
	{
		LSR_SET_ERRNO_MISSING();
		return -1;
	}

	if ( __lsr_can_wipe_filename (path) == 0 )
	{
		LSR_SET_ERRNO (err);
		return (*__lsr_real_truncate64_location ()) (path, length);
	}

#ifdef HAVE_UNISTD_H	/* need close(fd) */
	if ( __lsr_real_open64_location () != NULL )
	{

		fd = (*__lsr_real_open64_location ()) ( path, O_WRONLY|O_EXCL );
		if ( fd < 0 )
		{
			LSR_SET_ERRNO (err);
			return (*__lsr_real_truncate64_location ()) (path, length);
		}
		__lsr_fd_truncate ( fd, length );
		close (fd);
	}
	else
#endif		/* unistd.h */
	if ( __lsr_real_fopen64_location () != NULL )
	{
		f = (*__lsr_real_fopen64_location ()) ( path, "r+x" );
		if ( f == NULL )
		{
			LSR_SET_ERRNO (err);
			return (*__lsr_real_truncate64_location ()) (path, length);
		}
		fd = fileno (f);
		if ( fd < 0 )
		{
			fclose (f);
			LSR_SET_ERRNO (err);
			return (*__lsr_real_truncate64_location ()) (path, length);
		}

		__lsr_fd_truncate ( fd, length );
		fclose (f);
	}
	else
	{
		/* Can't open file */
		LSR_SET_ERRNO (err);
		return (*__lsr_real_truncate64_location ()) (path, length);
	}

	LSR_SET_ERRNO (err);
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
	LSR_MAKE_ERRNO_VAR(err);

	__lsr_main ();
#ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: ftruncate(%d, %ld)\n", fd, length);
	fflush (stderr);
#endif

	if ( __lsr_real_ftruncate_location () == NULL )
	{
		LSR_SET_ERRNO_MISSING();
		return -1;
	}

	if ( __lsr_can_wipe_filedesc (fd) == 0 )
	{
		LSR_SET_ERRNO (err);
		return (*__lsr_real_ftruncate_location ()) (fd, length);
	}
	__lsr_fd_truncate ( fd, length*((off64_t) 1) );

	LSR_SET_ERRNO (err);
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
	LSR_MAKE_ERRNO_VAR(err);

	__lsr_main ();
#ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: ftruncate64(%d, %lld)\n", fd, length);
	fflush (stderr);
#endif

	if ( __lsr_real_ftruncate64_location () == NULL )
	{
		LSR_SET_ERRNO_MISSING();
		return -1;
	}

	if ( __lsr_can_wipe_filedesc (fd) == 0 )
	{
		LSR_SET_ERRNO (err);
		return (*__lsr_real_ftruncate64_location ()) (fd, length);
	}
	__lsr_fd_truncate ( fd, length );

	LSR_SET_ERRNO (err);
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

#if (defined HAVE_SYS_STAT_H) && (defined HAVE_FSTAT64)
	struct stat64 s;
#endif
	LSR_MAKE_ERRNO_VAR(err); /* posix_fallocate does NOT set errno. */
	int res;

	__lsr_main ();
#ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: posix_fallocate(%d, %lld, %lld)\n",
		fd, offset, len);
	fflush (stderr);
#endif

	if ( __lsr_real_posix_fallocate_location () == NULL )
	{
		LSR_SET_ERRNO_MISSING();
		return -1;
	}

	if ( __lsr_can_wipe_filedesc (fd) == 0 )
	{
		LSR_SET_ERRNO (err);
		return (*__lsr_real_posix_fallocate_location ()) (fd, offset, len);
	}

#if (!defined HAVE_SYS_STAT_H) || (!defined HAVE_FSTAT64)
	/* Sorry, can't truncate something I can't fstat().
	This would cause problems. */
	LSR_SET_ERRNO (err);
	return (*__lsr_real_posix_fallocate_location ()) (fd, offset, len);
#else
	if ( fstat64 (fd, &s) == 0 )
	{
		/* don't operate on non-files */
		if ( ! S_ISREG (s.st_mode) )
		{
			LSR_SET_ERRNO (err);
			return (*__lsr_real_posix_fallocate_location ()) (fd, offset, len);
		}
	}
	else
	{
		LSR_SET_ERRNO (err);
		return (*__lsr_real_posix_fallocate_location ()) (fd, offset, len);
	}
#endif

	LSR_SET_ERRNO (err);
	res = (*__lsr_real_posix_fallocate_location ()) (fd, offset, len);
	LSR_GET_ERRNO(err);
	if ( (res == 0) && (offset + len > s.st_size) )
	{
		/* success and we're exceeding the current file size. */
		/* truncate the file back to its original size: */
		__lsr_fd_truncate ( fd, /*offset+len -*/ s.st_size );

	} /* if ( res == 0 ) */

	LSR_SET_ERRNO (err);
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

#if (defined HAVE_SYS_STAT_H) && (defined HAVE_FSTAT64)
	struct stat64 s;
#endif
	LSR_MAKE_ERRNO_VAR(err);
	int res;

	__lsr_main ();
#ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: fallocate(%d, %lld, %lld)\n",
		fd, offset, len);
	fflush (stderr);
#endif

	if ( __lsr_real_fallocate_location () == NULL )
	{
		LSR_SET_ERRNO_MISSING();
		return -1;
	}

	if ( __lsr_can_wipe_filedesc (fd) == 0 )
	{
		LSR_SET_ERRNO (err);
		return (*__lsr_real_fallocate_location ()) (fd, mode, offset, len);
	}
	if ( ((mode & FALLOC_FL_KEEP_SIZE) == FALLOC_FL_KEEP_SIZE)
		&& (__lsr_real_ftruncate64_location () == NULL) )
	{
		/* we're supposed to keep the file size unchanged, but
		   we can't truncate it - leave. */
		LSR_SET_ERRNO (err);
		return (*__lsr_real_fallocate_location ()) (fd, mode, offset, len);
	}

#if (!defined HAVE_SYS_STAT_H) || (!defined HAVE_FSTAT64)
	/* Sorry, can't truncate something I can't fstat().
	This would cause problems. */
	LSR_SET_ERRNO (err);
	return (*__lsr_real_fallocate_location ()) (fd, mode, offset, len);
#else
	if ( fstat64 (fd, &s) == 0 )
	{
		/* don't operate on non-files */
		if ( ! S_ISREG (s.st_mode) )
		{
			LSR_SET_ERRNO (err);
			return (*__lsr_real_fallocate_location ()) (fd, mode, offset, len);
		}
	}
	else
	{
		LSR_SET_ERRNO (err);
		return (*__lsr_real_fallocate_location ()) (fd, mode, offset, len);
	}
#endif

	LSR_SET_ERRNO (err);
	res = (*__lsr_real_fallocate_location ()) (fd, mode, offset, len);
	LSR_GET_ERRNO(err);
	if ( (res == 0) && (offset + len > s.st_size) )
	{
		/* success and we're exceeding the current file size. */
		/* truncate the file back to its original size: */
		__lsr_fd_truncate ( fd, /*offset+len -*/ s.st_size );
		if ( (mode & FALLOC_FL_KEEP_SIZE) == FALLOC_FL_KEEP_SIZE )
		{
			/* we're supposed to keep the file size unchanged,
				so truncate the file back. */
			(*__lsr_real_ftruncate64_location ()) (fd, s.st_size);
		}

	} /* if ( res == 0 ) */

	LSR_SET_ERRNO (err);
	return res;
}
