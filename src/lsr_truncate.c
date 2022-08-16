/*
 * A library for secure removing files.
 *	-- file truncating functions' replacements.
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

#ifndef _GNU_SOURCE
# define _GNU_SOURCE	1	/* need F_SETLEASE & fsync() */
#endif

#ifdef HAVE_STRING_H
# if (!STDC_HEADERS) && (defined HAVE_MEMORY_H)
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

#ifdef HAVE_MALLOC_H
# include <malloc.h>
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

#ifdef HAVE_STDLIB_H
# include <stdlib.h>	/* random(), rand() */
#endif

#include "libsecrm-priv.h"

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

const unsigned long int npasses = PASSES;	/* Number of passes (patterns used) */

/* Taken from `shred' source */
static unsigned const int patterns[NPAT] =
{
	0x000, 0xFFF,					/* 1-bit */
	0x555, 0xAAA,					/* 2-bit */
	0x249, 0x492, 0x6DB, 0x924, 0xB6D, 0xDB6,	/* 3-bit */
	0x111, 0x222, 0x333, 0x444, 0x666, 0x777,
	0x888, 0x999, 0xBBB, 0xCCC, 0xDDD, 0xEEE	/* 4-bit */
#ifndef LSR_WANT_RANDOM
	/* Gutmann method says these are used twice. */
	, 0x555, 0xAAA, 0x249, 0x492, 0x924
#endif
};

/* ======================================================= */

/**
 * Fills the given buffer with one of predefined patterns.
 * \param pat_no Pass number.
 * \param buffer Buffer to be filled.
 * \param buflen Length of the buffer.
 * \param selected array with 0s or 1s telling which patterns are already selected
 */
static void LSR_ATTR ((nonnull))
fill_buffer (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
		unsigned long int 		pat_no,
		unsigned char * const 		buffer,
		const size_t 			buflen,
		int * const			selected )
#else
	pat_no, buffer, buflen, selected )
		unsigned long int 		pat_no;
		unsigned char * const 		buffer;
		const size_t 			buflen;
		int * const			selected;
#endif
		/*@requires notnull buffer @*/ /*@sets *buffer @*/
{

	size_t i;
#if (!defined HAVE_MEMCPY) && (!defined HAVE_STRING_H)
	size_t j;
#endif
	unsigned int bits;

	if ( (buffer == NULL) || (buflen == 0) ) return;

	/* De-select all patterns once every npasses calls. */
	if ( pat_no % npasses == 0 )
	{
		for ( i = 0; i < NPAT; i++ ) { selected[i] = 0; }
        }
        pat_no %= npasses;

	/* The first, last and middle passess will be using a random pattern */
	if ( (pat_no == 0) || (pat_no == npasses-1) || (pat_no == npasses/2)
#ifndef LSR_WANT_RANDOM
		/* Gutmann method: first 4, 1 middle and last 4 passes are random */
		|| (pat_no == 1) || (pat_no == 2) || (pat_no == 3)
		|| (pat_no == npasses-2) || (pat_no == npasses-3) || (pat_no == npasses-4)
#endif
	 )
	{
#if (!defined __STRICT_ANSI__) && (defined HAVE_SRANDOM) && (defined HAVE_RANDOM)
		bits = (unsigned int) (random () & 0xFFF);
#else
		bits = (unsigned int) (__lsr_rand () & 0xFFF);
#endif
	}
	else
	{
		/* For other passes, one of the fixed patterns is selected. */
		do
		{
#if (!defined __STRICT_ANSI__) && (defined HAVE_SRANDOM) && (defined HAVE_RANDOM)
			i = (size_t) (random () % NPAT);
#else
			i = (size_t) (__lsr_rand () % NPAT);
#endif
		}
		while ( selected[i] == 1 );
		bits = patterns[i];
		selected[i] = 1;
    	}

	/* Taken from `shred' source and modified */
	bits |= bits << 12;
	buffer[0] = (unsigned char) ((bits >> 4) & 0xFF);
	buffer[1] = (unsigned char) ((bits >> 8) & 0xFF);
	buffer[2] = (unsigned char) (bits & 0xFF);

#ifdef LSR_DEBUG
	if ( (pat_no == 0) || (pat_no == npasses-1) || (pat_no == npasses/2)
# ifndef LSR_WANT_RANDOM
		/* Gutmann method: first 4, 1 middle and last 4 passes are random */
		|| (pat_no == 1) || (pat_no == 2) || (pat_no == 3)
		|| (pat_no == npasses-2) || (pat_no == npasses-3) || (pat_no == npasses-4)
# endif
	 )
	{
		fprintf (stderr, "Using pattern (random)\n");
	}
	else fprintf (stderr, "Using pattern %02x%02x%02x\n", buffer[0], buffer[1], buffer[2] );
#endif

	for (i = 3; i < buflen / 2; i *= 2)
	{
#ifdef HAVE_MEMCPY
		memcpy (buffer + i, buffer, i);
#else
# if defined HAVE_STRING_H
		strncpy ((char *) (buffer + i), (char *)buffer, i);
# else
		for ( j=0; j<i; j++ )
		{
			buffer [ i + j ] = buffer[j];
		}
# endif
#endif
	}
	if (i < buflen)
	{
#ifdef HAVE_MEMCPY
		memcpy (buffer + i, buffer, buflen - i);
#else
# if defined HAVE_STRING_H
		strncpy ((char *) (buffer + i), (char *)buffer, buflen - i);
# else
		for ( j = 0; j < buflen - i; j++ )
		{
			buffer [j+i] = buffer [j];
		}
# endif
#endif
	}
}

/* ======================================================= */

#ifdef HAVE_UNISTD_H
int
__lsr_fd_truncate (
# if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	const int fd, const off64_t length)
# else
	fd, length)
	const int fd;
	const off64_t length;
# endif
{

	unsigned char /*@only@*/ *buf = NULL;		/* Buffer to be written to file blocks */
	int selected[NPAT];

# ifndef HAVE_LONG_LONG
	unsigned long diff;
# else
	unsigned long long diff;
# endif
	off64_t size;
	off64_t pos;

	ssize_t write_res;
	unsigned int i, j;
# undef	N_BYTES
# define N_BYTES	1024
	const size_t buffer_size = sizeof (unsigned char) * N_BYTES;

	if ( fd < 0 )
	{
		return -1;
	}

	__lsr_main ();
# ifdef LSR_DEBUG
#  ifndef HAVE_LONG_LONG
	fprintf (stderr, "libsecrm: __lsr_fd_truncate(fd=%d, len=%ld)\n", fd, length);
#  else
	fprintf (stderr, "libsecrm: __lsr_fd_truncate(fd=%d, len=%lld)\n", fd, length);
#  endif
	fflush (stderr);
# endif

	/* save the current position */
# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
# if (defined HAVE_LONG_LONG) && ( \
	defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)	\
	)
	pos = lseek64 ( fd, 0LL, SEEK_CUR );
# else
	pos = lseek64 ( fd, 0, SEEK_CUR );
# endif
# ifdef HAVE_ERRNO_H
	/*
	if ( errno != 0 )
	{
		return -1;
	}*/
# endif

	/* find the file size */
# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
# if (defined HAVE_LONG_LONG) && ( \
	defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)	\
	)
	size = lseek64 ( fd, 0LL, SEEK_END );
# else
	size = lseek64 ( fd, 0, SEEK_END );
# endif
# ifdef HAVE_ERRNO_H
	/*
	if ( errno != 0 )
	{
		lseek64 ( fd, pos, SEEK_SET );
		return -1;
	}*/
# endif

# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	lseek64 ( fd, pos, SEEK_SET );
# ifdef HAVE_ERRNO_H
	/*
	if ( errno != 0 )
	{
		return -1;
	}*/
# endif

	if ( (size == 0) || (length >= size) )
	{
		/* Nothing to do */
		return 0;
	}

	/* seeking to correct position */
# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	if ( (lseek64 (fd, length, SEEK_SET) != length)
# ifdef HAVE_ERRNO_H
/*		|| (errno != 0)*/
# endif
	   )
	{
		/* Unable to set current file position. */
		return -1;
	}


	if ( sig_recvd != 0 )
	{
		lseek64 ( fd, pos, SEEK_SET );
		return -1;
	}
	diff = size - length;

	/* =========== Wiping loop ============== */

	if ( diff < BUF_SIZE )
	{
		/* We know 'diff' < BUF_SIZE < ULONG_MAX here, so it's safe to cast */
		buf = (unsigned char *) malloc ( sizeof(unsigned char)*(unsigned long) diff );
	}
	if ( (diff >= BUF_SIZE) || (buf == NULL) )
	{

# ifdef HAVE_ERRNO_H
		errno = 0;
# endif
		buf = (unsigned char *) malloc ( buffer_size );
		if ( (buf == NULL)
# ifdef HAVE_ERRNO_H
/*			|| (errno != 0)*/
# endif
		   )
		{
			/* Unable to get any memory. */
			lseek64 ( fd, pos, SEEK_SET );
			free (buf);
			return -1;
		}
		for ( j = 0; (j < npasses) && (sig_recvd == 0); j++ )
		{
			fill_buffer ( j, buf, buffer_size, selected );

			for ( i = 0; (i < diff/buffer_size) && (sig_recvd == 0); i++ )
			{
# ifdef HAVE_ERRNO_H
				errno = 0;
# endif
				write_res = write (fd, buf, buffer_size);
				if ( (write_res != (ssize_t)buffer_size)
# ifdef HAVE_ERRNO_H
/*					|| (errno != 0)*/
# endif
				   )
					break;
			}
# ifdef HAVE_ERRNO_H
			errno = 0;
# endif
			write_res = write (fd, buf, sizeof(unsigned char)*((size_t) diff)%N_BYTES);
			if ( (write_res != (ssize_t)(sizeof(unsigned char)*((unsigned long)diff)%N_BYTES))
# ifdef HAVE_ERRNO_H
/*				|| (errno != 0)*/
# endif
			   )
			{
				break;
			}

			if ( npasses > 1 )
			{
				fsync (fd);
			}
			/* go back to the start position of writing */
			if ( lseek64 ( fd, length, SEEK_SET) != length )
			{
				/* Unable to set current file position. */
				break;
			}
		}
		free (buf);

	}
	else if ( buf != NULL )
	{

		for ( j = 0; (j < npasses) && (sig_recvd == 0); j++ )
		{
			/* We know 'diff' < BUF_SIZE < ULONG_MAX here, so it's safe to cast */
			fill_buffer ( j, buf, sizeof(unsigned char)*(unsigned long)diff, selected );
# ifdef HAVE_ERRNO_H
			errno = 0;
# endif
			write_res = write (fd, buf, sizeof(unsigned char)*(unsigned long)diff);
			if ( (write_res != (ssize_t)((unsigned long)diff*sizeof(unsigned char)))
# ifdef HAVE_ERRNO_H
/*				|| (errno != 0)*/
# endif
			   )
			{
				break;
			}

			if ( npasses > 1 )
			{
				fsync (fd);
			}
			/* go back to the start position of writing */
			if ( lseek64 (fd, length, SEEK_SET) != length )
			{
				/* Unable to set current file position. */
				break;
			}
		}
		free (buf);
	}

	lseek64 ( fd, pos, SEEK_SET );
	return 0;
}
#endif	/* unistd.h */

/* ======================================================= */

#ifdef truncate
# undef truncate
#endif

int
truncate (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
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

	if ( __lsr_real_truncate == NULL )
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
		return (*__lsr_real_truncate) (path, length);
	}

	if ( strlen (path) == 0 )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_truncate) (path, length);
	}

#ifdef HAVE_SYS_STAT_H
# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	if ( stat (path, &s) == 0 )
	{

		/* don't operate on non-files */
		if ( (!S_ISREG (s.st_mode)) && (!S_ISLNK (s.st_mode)) )
		{
# ifdef HAVE_ERRNO_H
			errno = err;
# endif
			return (*__lsr_real_truncate) (path, length);
		}
	}
	else
	{
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		return (*__lsr_real_truncate) (path, length);
	}

	if ( (__lsr_check_prog_ban () != 0) || (__lsr_check_file_ban (path) != 0)
		|| (__lsr_check_file_ban_proc (path) != 0) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_truncate) (path, length);
	}

	/* opening the file in exclusive mode */

# ifdef HAVE_UNISTD_H	/* need close(fd) */
	if ( __lsr_real_open != NULL )
	{

#  ifdef HAVE_ERRNO_H
		errno = 0;
#  endif
		fd = (*__lsr_real_open) ( path, O_WRONLY|O_EXCL );
		if ( (fd < 0)
#  ifdef HAVE_ERRNO_H
/*			|| (errno != 0)*/
#  endif
		   )
		{
#  ifdef HAVE_UNISTD_H
/*			if ( fd > 0 ) close (fd);*/
#  endif
#  ifdef HAVE_ERRNO_H
			errno = err;
#  endif
			return (*__lsr_real_truncate) (path, length);
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
#   if (defined HAVE_LONG_LONG) && ( \
	defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)	\
	)
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
	if ( __lsr_real_fopen != NULL )
	{

# ifdef HAVE_ERRNO_H
		errno = 0;
# endif
		f = (*__lsr_real_fopen) ( path, "r+x" );

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
			return (*__lsr_real_truncate) (path, length);
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
			return (*__lsr_real_truncate) (path, length);
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
#  if (defined HAVE_LONG_LONG) && ( \
	defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)	\
	)
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
		return (*__lsr_real_truncate) (path, length);
	}
#endif		/* sys/stat.h */

#ifdef HAVE_ERRNO_H
	errno = err;
#endif
	return (*__lsr_real_truncate) (path, length);
}
/* ======================================================= */

#ifdef truncate64
# undef truncate64
#endif

int
truncate64 (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
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

	if ( __lsr_real_truncate64 == NULL )
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
		return (*__lsr_real_truncate64) (path, length);
	}

	if ( strlen (path) == 0 )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_truncate64) (path, length);
	}

#ifdef HAVE_SYS_STAT_H
# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	if ( stat64 (path, &s) == 0 )
	{
		/* don't operate on non-files */
		if ( (!S_ISREG (s.st_mode)) && (!S_ISLNK (s.st_mode)) )
		{
# ifdef HAVE_ERRNO_H
			errno = err;
# endif
			return (*__lsr_real_truncate64) (path, length);
		}
	}
	else
	{
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		return (*__lsr_real_truncate64) (path, length);
	}

	if ( (__lsr_check_prog_ban () != 0) || (__lsr_check_file_ban (path) != 0)
		|| (__lsr_check_file_ban_proc (path) != 0) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_truncate64) (path, length);
	}

# ifdef HAVE_UNISTD_H	/* need close(fd) */
	if ( __lsr_real_open64 != NULL )
	{

#  ifdef HAVE_ERRNO_H
		errno = 0;
#  endif
		fd = (*__lsr_real_open64) ( path, O_WRONLY|O_EXCL );
		if ( (fd < 0)
#  ifdef HAVE_ERRNO_H
/*			|| (errno != 0)*/
#  endif
		   )
		{
/*			if ( fd > 0 ) close (fd);*/
#  ifdef HAVE_ERRNO_H
			errno = err;
#  endif
			return (*__lsr_real_truncate64) (path, length);
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
	if ( __lsr_real_fopen64 != NULL )
	{
# ifdef HAVE_ERRNO_H
		errno = 0;
# endif
		f = (*__lsr_real_fopen64) ( path, "r+x" );
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
			return (*__lsr_real_truncate64) (path, length);
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
			return (*__lsr_real_truncate64) (path, length);
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
		return (*__lsr_real_truncate64) (path, length);
	}
#endif		/* sys/stat.h */

#ifdef HAVE_ERRNO_H
	errno = err;
#endif
	return (*__lsr_real_truncate64) (path, length);
}

/* ======================================================= */

#ifdef ftruncate
# undef ftruncate
#endif

int
ftruncate (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
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

	if ( __lsr_real_ftruncate == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = -ENOSYS;
#endif
		return -1;
	}

	if ( __lsr_check_prog_ban () != 0 )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_ftruncate) (fd, length);
	}

#ifdef HAVE_SYS_STAT_H
# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	if ( fstat (fd, &s) == 0 )
	{
		/* don't operate on non-files */
		if ( (!S_ISREG (s.st_mode)) && (!S_ISLNK (s.st_mode)) )
		{
# ifdef HAVE_ERRNO_H
			errno = err;
# endif
			return (*__lsr_real_ftruncate) (fd, length);
		}
	}
	else
	{
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		return (*__lsr_real_ftruncate) (fd, length);
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
#  if (defined HAVE_LONG_LONG) && ( \
	defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)	\
	)
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
	return (*__lsr_real_ftruncate) (fd, length);
}

/* ======================================================= */

#ifdef ftruncate64
# undef ftruncate64
#endif

int
ftruncate64 (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
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

	if ( __lsr_real_ftruncate64 == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = -ENOSYS;
#endif
		return -1;
	}

	if ( __lsr_check_prog_ban () != 0 )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_ftruncate64) (fd, length);
	}

#ifdef HAVE_SYS_STAT_H
# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	if ( fstat64 (fd, &s) == 0 )
	{
		/* don't operate on non-files */
		if ( (!S_ISREG (s.st_mode)) && (!S_ISLNK (s.st_mode)) )
		{
# ifdef HAVE_ERRNO_H
			errno = err;
# endif
			return (*__lsr_real_ftruncate64) (fd, length);
		}
	}
	else
	{
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		return (*__lsr_real_ftruncate64) (fd, length);
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
	return (*__lsr_real_ftruncate64) (fd, length);
}
