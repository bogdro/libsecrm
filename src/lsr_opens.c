/*
 * A library for secure removing files.
 *	-- file opening functions' replacements.
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

#include "lsr_cfg.h"

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

#ifdef HAVE_STRING_H
# if (!STDC_HEADERS) && (defined HAVE_MEMORY_H)
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

#include "libsecrm.h"

#ifdef __GNUC__
# pragma GCC poison unlink unlinkat remove
#endif

/* ======================================================= */

#ifdef LSR_USE64
FILE*
fopen64 (const char * const name, const char * const mode)
{
# ifdef __GNUC__
#  pragma GCC poison fopen64
# endif

# ifdef HAVE_ERRNO_H
	int err = 0;
# endif
	__lsr_main ();

# ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: fopen64(%s, %s)\n", (name==NULL)? "null" : name, (mode==NULL)? "null" : mode);
	fflush (stderr);
# endif

	if ( __lsr_real_fopen64 == NULL )
	{
# ifdef HAVE_ERRNO_H
		errno = ENOSYS;
# endif
		return NULL;
	}

	if ( (name == NULL) || (mode == NULL) )
	{
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		return (*__lsr_real_fopen64) (name, mode);
	}

	if ( (strlen (name) == 0) || (strlen (mode) == 0) )
	{
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		return (*__lsr_real_fopen64) (name, mode);
	}

	if ( (strchr (mode, (int)'w') != NULL) || (strchr (mode, (int)'W') != NULL) )
	{
		truncate64 (name, 0LL);
	}

# ifdef HAVE_ERRNO_H
	errno = err;
# endif
	return (*__lsr_real_fopen64) (name, mode);
}

/* ======================================================= */
#else /* LSR_USE64 */

FILE*
fopen (const char * const name, const char * const mode)
{
# ifdef __GNUC__
#  pragma GCC poison fopen
# endif

# ifdef HAVE_ERRNO_H
	int err = 0;
# endif

	__lsr_main ();

# ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: fopen(%s, %s)\n", (name==NULL)? "null" : name, (mode==NULL)? "null" : mode);
	fflush (stderr);
# endif

	if ( __lsr_real_fopen == NULL )
	{
# ifdef HAVE_ERRNO_H
		errno = ENOSYS;
# endif
		return NULL;
	}

	if ( (name == NULL) || (mode == NULL) )
	{
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		return (*__lsr_real_fopen) (name, mode);
	}

	if ( (strlen (name) == 0) || (strlen (mode) == 0) )
	{
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		return (*__lsr_real_fopen) (name, mode);
	}

	if ( (strchr (mode, (int)'w') != NULL) || (strchr (mode, (int)'W') != NULL) )
	{
		truncate (name, 0);
	}

# ifdef HAVE_ERRNO_H
	errno = err;
# endif
	return (*__lsr_real_fopen) (name, mode);
}
#endif
/* ======================================================= */

#ifdef LSR_USE64
FILE*
freopen64 (const char * const path, const char * const mode, FILE* stream)
{
# ifdef __GNUC__
#  pragma GCC poison freopen64
# endif

# ifdef HAVE_ERRNO_H
	int err = 0;
# endif
	int fd;

	__lsr_main ();
# ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: freopen64(%s, %s, %ld)\n",
		(path==NULL)? "null" : path, (mode==NULL)? "null" : mode, (long)stream);
	fflush (stderr);
# endif

	if ( __lsr_real_freopen64 == NULL )
	{
# ifdef HAVE_ERRNO_H
		errno = ENOSYS;
# endif
		return NULL;
	}

	if ( (path == NULL) || (mode == NULL) || (stream == NULL) )
	{
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		return (*__lsr_real_freopen64) ( path, mode, stream );
	}

	if ( (strlen (path) == 0) || (strlen (mode) == 0) || (stream == stdin)
		|| (stream == stdout) || (stream == stderr)
	   )
	{
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		return (*__lsr_real_freopen64) ( path, mode, stream );
	}

	if ( (strchr (mode, (int)'w') != NULL) || (strchr (mode, (int)'W') != NULL) )
	{
# ifdef HAVE_ERRNO_H
		errno = 0;
# endif
		fd = fileno (stream);
		if ( (fd < 0)
# ifdef HAVE_ERRNO_H
			|| (errno != 0)
# endif
		   )
		{
			fflush (stream);
			rewind (stream);
			truncate64 (path, 0LL);
		}
		fflush (stream);
		rewind (stream);
		ftruncate64 (fd, 0LL);
	}

# ifdef HAVE_ERRNO_H
	errno = err;
# endif
	return (*__lsr_real_freopen64) ( path, mode, stream );
}
#else /* LSR_USE64 */

/* ======================================================= */

FILE*
freopen (const char * const path, const char * const mode, FILE* stream)
{
# ifdef __GNUC__
#  pragma GCC poison freopen
# endif

# ifdef HAVE_ERRNO_H
	int err = 0;
# endif
	int fd;

	__lsr_main ();
# ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: freopen(%s, %s, %ld)\n",
		(path==NULL)? "null" : path, (mode==NULL)? "null" : mode, (long)stream);
	fflush (stderr);
# endif

	if ( __lsr_real_freopen == NULL )
	{
# ifdef HAVE_ERRNO_H
		errno = ENOSYS;
# endif
		return NULL;
	}

	if ( (path == NULL) || (mode == NULL) || (stream == NULL) )
	{
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		return (*__lsr_real_freopen) ( path, mode, stream );
	}

	if ( (strlen (path) == 0) || (strlen (mode) == 0) || (stream == stdin)
		|| (stream == stdout) || (stream == stderr)
	   )
	{
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		return (*__lsr_real_freopen) ( path, mode, stream );
	}

	if ( (strchr (mode, (int)'w') != NULL) || (strchr (mode, (int)'W') != NULL) )
	{
# ifdef HAVE_ERRNO_H
		errno = 0;
# endif
		fd = fileno (stream);
		if ( (fd < 0)
# ifdef HAVE_ERRNO_H
			|| (errno != 0)
# endif
		   )
		{
			fflush (stream);
			rewind (stream);
			truncate (path, 0);
		}
		fflush (stream);
		rewind (stream);
		ftruncate (fd, 0);
	}

# ifdef HAVE_ERRNO_H
	errno = err;
# endif
	return (*__lsr_real_freopen) ( path, mode, stream );
}
#endif /* LSR_USE64 */

/* ======================================================= */

/* 'man 2 open' gives:
    int open(const char *pathname, int flags);
    int open(const char *pathname, int flags, mode_t mode);
   'man 3p open' (POSIX) & /usr/include/fcntl.h give:
    int open(const char *path, int oflag, ...  );
 */

#ifdef LSR_USE64
int
open64 (const char * const path, const int flags, ... )
{
# ifdef __GNUC__
#  pragma GCC poison open64
# endif

	va_list args;
	int ret_fd, mode;
# ifdef HAVE_ERRNO_H
	int err = 0;
# endif

	__lsr_main ();
# ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: open64(%s, %d, ...)\n", (path==NULL)? "null" : path, flags);
	fflush (stderr);
# endif

	if ( __lsr_real_open64 == NULL )
	{
# ifdef HAVE_ERRNO_H
		errno = ENOSYS;
# endif
		return -1;
	}

	va_start (args, flags);
	mode = va_arg (args, int);

	if ( path == NULL )
	{
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		ret_fd = (*__lsr_real_open64) ( path, flags, mode );
# ifdef HAVE_ERRNO_H
		err = errno;
# endif
		va_end (args);
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		return ret_fd;
	}

	if ( strlen (path) == 0 )
	{
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		ret_fd = (*__lsr_real_open64) ( path, flags, mode );
# ifdef HAVE_ERRNO_H
		err = errno;
# endif
		va_end (args);
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		return ret_fd;
	}

	if ( ((flags & O_TRUNC) == O_TRUNC)
		&& (
		((flags & O_WRONLY) == O_WRONLY) || ((flags & O_RDWR) == O_RDWR)
		   )
	   )
	{
		truncate64 (path, 0LL);
	}

# ifdef HAVE_ERRNO_H
	errno = err;
# endif
	ret_fd = (*__lsr_real_open64) ( path, flags, mode );
# ifdef HAVE_ERRNO_H
	err = errno;
# endif
	va_end (args);
# ifdef HAVE_ERRNO_H
	errno = err;
# endif

	return ret_fd;
}
#else /* LSR_USE64 */

/* ======================================================= */

int
open (const char * const path, const int flags, ... )
{
# ifdef __GNUC__
#  pragma GCC poison open
# endif

	va_list args;
	int ret_fd, mode;
# ifdef HAVE_ERRNO_H
	int err = 0;
# endif

	__lsr_main ();
# ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: open(%s, %d, ...)\n", (path==NULL)? "null" : path, flags);
	fflush (stderr);
# endif

	if ( __lsr_real_open == NULL )
	{
# ifdef HAVE_ERRNO_H
		errno = ENOSYS;
# endif
		return -1;
	}

	va_start (args, flags);
	mode = va_arg (args, int);

	if ( path == NULL )
	{
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		ret_fd = (*__lsr_real_open) ( path, flags, mode );
# ifdef HAVE_ERRNO_H
		err = errno;
# endif
		va_end (args);
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		return ret_fd;
	}

	if ( strlen (path) == 0 )
	{
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		ret_fd = (*__lsr_real_open) ( path, flags, mode );
# ifdef HAVE_ERRNO_H
		err = errno;
# endif
		va_end (args);
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		return ret_fd;
	}

	if ( ((flags & O_TRUNC) == O_TRUNC)
		&& (
		((flags & O_WRONLY) == O_WRONLY) || ((flags & O_RDWR) == O_RDWR)
		   )
	   )
	{
		truncate (path, 0);
	}

# ifdef HAVE_ERRNO_H
	errno = err;
# endif
	ret_fd = (*__lsr_real_open) ( path, flags, mode );
# ifdef HAVE_ERRNO_H
	err = errno;
# endif
	va_end (args);
# ifdef HAVE_ERRNO_H
	errno = err;
# endif

	return ret_fd;
}
#endif	/* LSR_USE64 */

/* ======================================================= */

#ifdef LSR_USE64
int
openat64 (const int dirfd, const char * const pathname, const int flags, ...)
{
# ifdef __GNUC__
#  pragma GCC poison openat64
# endif

	int fd, ret_fd, mode;
	va_list args;
# ifdef HAVE_ERRNO_H
	int err = 0;
# endif

	__lsr_main ();

# ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: openat64(%d, %s, %d, ...)\n",
		dirfd, (pathname==NULL)? "null" : pathname, flags);
	fflush (stderr);
# endif

	if ( __lsr_real_openat64 == NULL )
	{
# ifdef HAVE_ERRNO_H
		errno = ENOSYS;
# endif
		return -1;
	}

	va_start (args, flags);
	mode = va_arg (args, int);

	if ( pathname == NULL )
	{
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		ret_fd = (*__lsr_real_openat64) ( dirfd, pathname, flags, mode );
# ifdef HAVE_ERRNO_H
		err = errno;
# endif
		va_end (args);
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		return ret_fd;
	}

	if ( strlen (pathname) == 0 )
	{
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		ret_fd = (*__lsr_real_openat64) ( dirfd, pathname, flags, mode );
# ifdef HAVE_ERRNO_H
		err = errno;
# endif
		va_end (args);
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		return ret_fd;
	}

	if ( ((flags & O_TRUNC) == O_TRUNC)
		&& (
		((flags & O_WRONLY) == O_WRONLY) || ((flags & O_RDWR) == O_RDWR)
		   )
	   )
	{


# ifdef HAVE_ERRNO_H
		errno = 0;
# endif
		fd = (*__lsr_real_openat64) (dirfd, pathname, O_WRONLY, S_IRUSR|S_IWUSR);
		if ( (fd >= 0)
# ifdef HAVE_ERRNO_H
			|| (errno == 0)
# endif
		   )
		{
			ftruncate64 (fd, 0LL);
			close (fd);
		}
	}
# ifdef HAVE_ERRNO_H
	errno = err;
# endif
	ret_fd = (*__lsr_real_openat64) ( dirfd, pathname, flags, mode );
# ifdef HAVE_ERRNO_H
	err = errno;
# endif
	va_end (args);
# ifdef HAVE_ERRNO_H
	errno = err;
# endif

	return ret_fd;
}
#else	/* LSR_USE64 */


/* ======================================================= */

/*/
int openat(int dirfd, const char *pathname, int flags);
int openat(int dirfd, const char *pathname, int flags, mode_t mode);
 */

int
openat (const int dirfd, const char * const pathname, const int flags, ...)
{
# ifdef __GNUC__
#  pragma GCC poison openat
# endif

	int fd, ret_fd, mode;
	va_list args;
# ifdef HAVE_ERRNO_H
	int err = 0;
# endif

	__lsr_main ();

# ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: openat(%d, %s, %d, ...)\n", dirfd, (pathname==NULL)? "null" : pathname, flags);
	fflush (stderr);
# endif

	if ( __lsr_real_openat == NULL )
	{
# ifdef HAVE_ERRNO_H
		errno = ENOSYS;
# endif
		return -1;
	}

	va_start (args, flags);
	mode = va_arg (args, int);

	if ( pathname == NULL )
	{
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		ret_fd = (*__lsr_real_openat) ( dirfd, pathname, flags, mode );
# ifdef HAVE_ERRNO_H
		err = errno;
# endif
		va_end (args);
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		return ret_fd;
	}

	if ( strlen (pathname) == 0 )
	{
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		ret_fd = (*__lsr_real_openat) ( dirfd, pathname, flags, mode );
# ifdef HAVE_ERRNO_H
		err = errno;
# endif
		va_end (args);
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		return ret_fd;
	}

	if ( ((flags & O_TRUNC) == O_TRUNC)
		&& (
		((flags & O_WRONLY) == O_WRONLY) || ((flags & O_RDWR) == O_RDWR)
		   )
	   )
	{


# ifdef HAVE_ERRNO_H
		errno = 0;
# endif
		fd = (*__lsr_real_openat) (dirfd, pathname, O_WRONLY, S_IRUSR|S_IWUSR);
		if ( (fd >= 0)
# ifdef HAVE_ERRNO_H
			|| (errno == 0)
# endif
		   )
		{
			ftruncate (fd, 0);
			close (fd);
		}
	}
# ifdef HAVE_ERRNO_H
	errno = err;
# endif
	ret_fd = (*__lsr_real_openat) ( dirfd, pathname, flags, mode );
# ifdef HAVE_ERRNO_H
	err = errno;
# endif
	va_end (args);
# ifdef HAVE_ERRNO_H
	errno = err;
# endif

	return ret_fd;
}
#endif /* LSR_USE64 */
