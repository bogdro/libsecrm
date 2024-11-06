/*
 * LibSecRm - A library for secure removing files.
 *	-- file truncating functions' replacements.
 *
 * Copyright (C) 2007-2024 Bogdan Drozdowski, bogdro (at) users . sourceforge . net
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
#else
# ifdef __cplusplus
extern "C" {
# endif

/* Only these need to be defined, because only these get called explicitly. */
extern int truncate LSR_PARAMS ((const char *path, off_t length));
# if (!defined truncate64)
extern int truncate64 LSR_PARAMS ((const char *path, off64_t length));
# endif
extern int ftruncate LSR_PARAMS ((int fd, off_t length));
# if (!defined ftruncate64)
extern int ftruncate64 LSR_PARAMS ((int fd, off64_t length));
# endif

# ifdef __cplusplus
}
# endif
#endif /* HAVE_UNISTD_H */

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
#  ifdef __cplusplus
extern "C" {
#  endif

# ifndef HAVE_TRUNCATE64
extern int truncate64 LSR_PARAMS((const char * const path, const off64_t length));
# endif
# ifndef HAVE_FTRUNCATE64
extern int ftruncate64 LSR_PARAMS((int fd, const off64_t length));
# endif

#  ifdef __cplusplus
}
#  endif
*/
/*#endif*/

#ifdef __cplusplus
extern "C" {
#endif

#ifndef HAVE_POSIX_FALLOCATE
extern int posix_fallocate LSR_PARAMS ((int fd, off_t offset, off_t len));
#endif
#ifndef HAVE_POSIX_FALLOCATE64
extern int posix_fallocate64 LSR_PARAMS((int __fd, off64_t __offset, off64_t __len));
#endif
#ifndef HAVE_FALLOCATE
extern int fallocate LSR_PARAMS ((int fd, int mode, off_t offset, off_t len));
#endif

#ifdef __cplusplus
}
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

#ifdef TEST_COMPILE
# undef LSR_ANSIC
#endif

/* ======================================================= */

#ifndef LSR_ANSIC
static int generic_truncate LSR_PARAMS((
	const char * const path, const int bits,
	const off_t length, const off64_t length64,
	const fp_cp_cp real_fopen, const i_cp_i_ real_open,
	const i_cp_o real_truncate, const i_cp_o64 real_truncate64));
#endif

static int
generic_truncate (
#ifdef LSR_ANSIC
	const char * const path, const int bits,
	const off_t length, const off64_t length64,
	const fp_cp_cp real_fopen, const i_cp_i_ real_open,
	const i_cp_o real_truncate, const i_cp_o64 real_truncate64)
#else
	path, bits, length, length64, real_fopen, real_open, real_truncate, real_truncate64)
	const char * const path;
	const int bits;
	const off_t length;
	const off64_t length64;
	const fp_cp_cp real_fopen;
	const i_cp_i_ real_open;
	const i_cp_o real_truncate;
	const i_cp_o64 real_truncate64;
#endif
{
	FILE *f;
	int fd;
	LSR_MAKE_ERRNO_VAR(err);

	if ( ((bits == 32) && (real_truncate == NULL))
		|| ((bits == 64) && (real_truncate64 == NULL)) )
	{
		LSR_SET_ERRNO_MISSING();
		return -1;
	}

	if ( __lsr_can_wipe_filename (path, 1) == 0 )
	{
		LSR_SET_ERRNO (err);
		if ( bits == 32 )
		{
			return (*real_truncate) (path, length);
		}
		else
		{
			return (*real_truncate64) (path, length64);
		}
	}

	/* opening the file in exclusive mode */
#ifdef HAVE_UNISTD_H	/* need close(fd) */
	if ( real_open != NULL )
	{
		fd = (*real_open) ( path, O_WRONLY|O_EXCL );
		if ( fd < 0 )
		{
			LSR_SET_ERRNO (err);
			if ( bits == 32 )
			{
				return (*real_truncate) (path, length);
			}
			else
			{
				return (*real_truncate64) (path, length64);
			}
		}

		__lsr_fd_truncate ( fd, length*((off64_t) 1) );
		close (fd);
	}
	else
#endif	/* unistd.h */
	if ( real_fopen != NULL )
	{
		f = (*real_fopen) ( path, "r+x" );

		if ( f == NULL )
		{
			LSR_SET_ERRNO (err);
			if ( bits == 32 )
			{
				return (*real_truncate) (path, length);
			}
			else
			{
				return (*real_truncate64) (path, length64);
			}
		}

		fd = fileno (f);
		if ( fd < 0 )
		{
			fclose (f);
			LSR_SET_ERRNO (err);
			if ( bits == 32 )
			{
				return (*real_truncate) (path, length);
			}
			else
			{
				return (*real_truncate64) (path, length64);
			}
		}

		__lsr_fd_truncate ( fd, length*((off64_t) 1) );
		fclose (f);
	}
	else
	{
		/* Can't open file */
		LSR_SET_ERRNO (err);
		if ( bits == 32 )
		{
			return (*real_truncate) (path, length);
		}
		else
		{
			return (*real_truncate64) (path, length64);
		}
	}

	LSR_SET_ERRNO (err);
	if ( bits == 32 )
	{
		return (*real_truncate) (path, length);
	}
	else
	{
		return (*real_truncate64) (path, length64);
	}
}

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

	__lsr_main ();
#ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: truncate(%s, %ld)\n",
		(path==NULL)? "null" : path, length);
	fflush (stderr);
#endif
	return generic_truncate (path, 32, length, (off64_t) 0,
		__lsr_real_fopen_location (), __lsr_real_open_location (),
		__lsr_real_truncate_location (), __lsr_real_truncate64_location ());
}

/* ======================================================= */

#ifdef HAVE_TRUNCATE64

# ifdef truncate64
#  undef truncate64
# endif

int
truncate64 (
# ifdef LSR_ANSIC
	const char * const path, const off64_t length)
# else
	path, length)
	const char * const path;
	const off64_t length;
# endif
{
# if (defined __GNUC__) && (!defined truncate64)
#  pragma GCC poison truncate64
# endif

	__lsr_main ();
# ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: truncate64(%s, %lld)\n",
		(path==NULL)? "null" : path, length);
	fflush (stderr);
# endif

	return generic_truncate (path, 64, 0, length,
		__lsr_real_fopen_location (), __lsr_real_open_location (),
		__lsr_real_truncate_location (), __lsr_real_truncate64_location ());
}
#endif /* HAVE_TRUNCATE64 */

/* ======================================================= */

#ifndef LSR_ANSIC
static int generic_ftruncate LSR_PARAMS((
	int fd, const int bits,
	const off_t length, const off64_t length64,
	const i_i_o real_ftruncate, const i_i_o64 real_ftruncate64));
#endif

static int
generic_ftruncate (
#ifdef LSR_ANSIC
	int fd, const int bits,
	const off_t length, const off64_t length64,
	const i_i_o real_ftruncate, const i_i_o64 real_ftruncate64)
#else
	fd, bits, length, length64, real_ftruncate, real_ftruncate64)
	int fd;
	const int bits;
	const off_t length;
	const off64_t length64;
	const i_i_o real_ftruncate;
	const i_i_o64 real_ftruncate64;
#endif
{
	LSR_MAKE_ERRNO_VAR(err);

	if ( ((bits == 32) && (real_ftruncate == NULL))
		|| ((bits == 64) && (real_ftruncate64 == NULL)) )
	{
		LSR_SET_ERRNO_MISSING();
		return -1;
	}

	if ( __lsr_can_wipe_filedesc (fd) == 0 )
	{
		LSR_SET_ERRNO (err);
		if ( bits == 32 )
		{
			return (*real_ftruncate) (fd, length);
		}
		else
		{
			return (*real_ftruncate64) (fd, length64);
		}
	}
	__lsr_fd_truncate ( fd, length*((off64_t) 1) );

	LSR_SET_ERRNO (err);
	if ( bits == 32 )
	{
		return (*real_ftruncate) (fd, length);
	}
	else
	{
		return (*real_ftruncate64) (fd, length64);
	}
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

	__lsr_main ();
#ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: ftruncate(%d, %ld)\n", fd, length);
	fflush (stderr);
#endif

	return generic_ftruncate (fd, 32, length, (off64_t) 0,
		__lsr_real_ftruncate_location (), __lsr_real_ftruncate64_location ());
}

/* ======================================================= */

#ifdef HAVE_FTRUNCATE64

# ifdef ftruncate64
#  undef ftruncate64
# endif

int
ftruncate64 (
# ifdef LSR_ANSIC
	int fd, const off64_t length)
# else
	fd, length)
	int fd;
	const off64_t length;
# endif
{
# if (defined __GNUC__) && (!defined ftruncate64)
#  pragma GCC poison ftruncate64
# endif

	__lsr_main ();
# ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: ftruncate64(%d, %lld)\n", fd, length);
	fflush (stderr);
# endif

	return generic_ftruncate (fd, 64, 0, length,
		__lsr_real_ftruncate_location (), __lsr_real_ftruncate64_location ());
}
#endif /* HAVE_FTRUNCATE64 */

/* ======================================================= */

#ifndef LSR_ANSIC
static int generic_posix_fallocate LSR_PARAMS((
	int fd, const int bits,
	const off_t offset, const off64_t offset64,
	const off_t length, const off64_t length64,
	const i_o_o real_posix_fallocate, const i_o64_o64 real_posix_fallocate64));
#endif

static int
generic_posix_fallocate (
#ifdef LSR_ANSIC
	int fd, const int bits,
	const off_t offset, const off64_t offset64,
	const off_t length, const off64_t length64,
	const i_o_o real_posix_fallocate, const i_o64_o64 real_posix_fallocate64)
#else
	fd, bits,
	offset, offset64,
	length, length64,
	real_posix_fallocate, real_posix_fallocate64)
	int fd;
	const int bits;
	const off_t offset;
	const off64_t offset64;
	const off_t length;
	const off64_t length64;
	const i_o_o real_posix_fallocate;
	const i_o64_o64 real_posix_fallocate64;
#endif
{
#if (defined HAVE_SYS_STAT_H)
# ifdef HAVE_STAT64
	struct stat64 s;
# else
#  ifdef HAVE_STAT
	struct stat s;
#  endif
# endif
#endif
	LSR_MAKE_ERRNO_VAR(err); /* posix_fallocate does NOT set errno. */
	int res;

	if ( ((bits == 32) && (real_posix_fallocate == NULL))
		|| ((bits == 64) && (real_posix_fallocate64 == NULL)) )
	{
		LSR_SET_ERRNO_MISSING();
		return -1;
	}

	if ( __lsr_can_wipe_filedesc (fd) == 0 )
	{
		LSR_SET_ERRNO (err);
		if ( bits == 32 )
		{
			return (*real_posix_fallocate) (fd, offset, length);
		}
		else
		{
			return (*real_posix_fallocate64) (fd, offset64, length64);
		}
	}
#if (!defined HAVE_SYS_STAT_H)
	/* Sorry, can't truncate something I can't fstat().
	This would cause problems. */
	LSR_SET_ERRNO (err);
	if ( bits == 32 )
	{
		return (*real_posix_fallocate) (fd, offset, length);
	}
	else
	{
		return (*real_posix_fallocate64) (fd, offset64, length64);
	}
#else
# ifdef HAVE_FSTAT64
	if ( fstat64 (fd, &s) == 0 )
# else
#  ifdef HAVE_FSTAT
	if ( fstat (fd, &s) == 0 )
#  else
	if ( 0 )
#  endif
# endif
	{
		/* don't operate on non-files */
		if ( ! S_ISREG (s.st_mode) )
		{
			LSR_SET_ERRNO (err);
			if ( bits == 32 )
			{
				return (*real_posix_fallocate) (fd, offset, length);
			}
			else
			{
				return (*real_posix_fallocate64) (fd, offset64, length64);
			}
		}
	}
	else
	{
		LSR_SET_ERRNO (err);
		if ( bits == 32 )
		{
			return (*real_posix_fallocate) (fd, offset, length);
		}
		else
		{
			return (*real_posix_fallocate64) (fd, offset64, length64);
		}
	}
#endif
	LSR_SET_ERRNO (err);
	if ( bits == 32 )
	{
		res = (*real_posix_fallocate) (fd, offset, length);
	}
	else
	{
		res = (*real_posix_fallocate64) (fd, offset64, length64);
	}
	LSR_GET_ERRNO(err);
	if ( res == 0 )
	{
		if ( (( bits == 32 ) && (offset + length > s.st_size) )
			|| (( bits == 64 ) && (offset64 + length64 > s.st_size) )
		)
		{
			/* success and we're exceeding the current file size. */
			/* truncate the file back to its original size: */
			__lsr_fd_truncate ( fd, /*offset+len -*/ s.st_size );
		}

	} /* if ( res == 0 ) */

	LSR_SET_ERRNO (err);
	return res;
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
	__lsr_main ();
#ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: posix_fallocate(%d, %lld, %lld)\n",
		fd, offset, len);
	fflush (stderr);
#endif
	return generic_posix_fallocate (fd, 32, offset, (off64_t) 0,
		len, (off64_t) 0, __lsr_real_posix_fallocate_location (),
		__lsr_real_posix_fallocate64_location ());
}

/* ======================================================= */

#ifdef HAVE_POSIX_FALLOCATE64

# ifdef posix_fallocate64
#  undef posix_fallocate64
# endif

int
posix_fallocate64 (
# ifdef LSR_ANSIC
	int fd, off64_t offset, off64_t len)
# else
	fd, offset, len)
	int fd;
	off64_t offset;
	off64_t len;
# endif
{
# if (defined __GNUC__) && (!defined posix_fallocate64)
#  pragma GCC poison posix_fallocate64
# endif
	__lsr_main ();
# ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: posix_fallocate64(%d, %lld, %lld)\n",
		fd, offset, len);
	fflush (stderr);
# endif
	return generic_posix_fallocate (fd, 64, 0, offset,
		0, len, __lsr_real_posix_fallocate_location (),
		__lsr_real_posix_fallocate64_location ());
}
#endif /* HAVE_POSIX_FALLOCATE64 */

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
# ifdef HAVE_STAT64
	struct stat64 s;
# else
#  ifdef HAVE_STAT
	struct stat s;
#  endif
# endif
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

#if (!defined HAVE_SYS_STAT_H)
	/* Sorry, can't truncate something I can't fstat().
	This would cause problems. */
	LSR_SET_ERRNO (err);
	return (*__lsr_real_fallocate_location ()) (fd, mode, offset, len);
#else
# ifdef HAVE_FSTAT64
	if ( fstat64 (fd, &s) == 0 )
# else
#  ifdef HAVE_FSTAT
	if ( fstat (fd, &s) == 0 )
#  else
	if ( 0 )
#  endif
# endif
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
