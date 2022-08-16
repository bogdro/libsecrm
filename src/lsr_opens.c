/*
 * A library for secure removing files.
 *	-- file opening functions' replacements.
 *
 * Copyright (C) 2007 Bogdan Drozdowski, bogdandr (at) op.pl
 * License: GNU General Public License, v2+
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
#include "libsecrm.h"

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

/* ======================================================= */

#ifdef __USE_LARGEFILE64
FILE*
fopen64 (const char * const name, const char * const mode)
{
	__lsr_main ();

# ifdef LSR_DEBUG
	printf ("libsecrm: fopen64()\n");
	fflush (stdout);
# endif

	if ( __lsr_real_fopen64 == NULL ) {
# ifdef HAVE_ERRNO_H
		errno = ENOSYS;
# endif
		return NULL;
	}

	if ( (name == NULL) || (mode == NULL) ) {
		return (*__lsr_real_fopen64) (name, mode);
	}

	if ( (strlen (name) == 0) || (strlen (mode) == 0) ) {
		return (*__lsr_real_fopen64) (name, mode);
	}

	if ( (strchr (mode, (int)'w') != NULL) || (strchr (mode, (int)'W') != NULL) ) {
		truncate64 (name, (off64_t)0);
	}

	return (*__lsr_real_fopen64) (name, mode);
}

/* ======================================================= */
#else /* __USE_LARGEFILE64 */

FILE*
fopen (const char * const name, const char * const mode)
{

	__lsr_main ();

# ifdef LSR_DEBUG
	printf ("libsecrm: fopen()\n");
	fflush (stdout);
# endif

	if ( __lsr_real_fopen == NULL ) {
# ifdef HAVE_ERRNO_H
		errno = ENOSYS;
# endif
		return NULL;
	}

	if ( (name == NULL) || (mode == NULL) ) {
		return (*__lsr_real_fopen) (name, mode);
	}

	if ( (strlen (name) == 0) || (strlen (mode) == 0) ) {
		return (*__lsr_real_fopen) (name, mode);
	}

	if ( (strchr (mode, (int)'w') != NULL) || (strchr (mode, (int)'W') != NULL) ) {
		truncate (name, 0);
	}

	return (*__lsr_real_fopen) (name, mode);
}
#endif
/* ======================================================= */

#ifdef __USE_LARGEFILE64
FILE*
freopen64 (const char * const path, const char * const mode, FILE* stream)
{

	__lsr_main ();
# ifdef LSR_DEBUG
	printf ("libsecrm: freopen64()\n");
	fflush (stdout);
# endif

	if ( __lsr_real_freopen64 == NULL ) {
# ifdef HAVE_ERRNO_H
		errno = ENOSYS;
# endif
		return NULL;
	}

	if ( (path == NULL) || (mode == NULL) || (stream == NULL) ) {
		return (*__lsr_real_freopen64) ( path, mode, stream );
	}

	if ( (strlen (path) == 0) || (strlen (mode) == 0) ) {
		return (*__lsr_real_freopen64) ( path, mode, stream );
	}

	if ( (strchr (mode, (int)'w') != NULL) || (strchr (mode, (int)'W') != NULL) ) {
		fflush (stream);
		rewind (stream);
		truncate64 (path, (off64_t)0);
	}

	return (*__lsr_real_freopen64) ( path, mode, stream );
}
#else /* __USE_LARGEFILE64 */

/* ======================================================= */

FILE*
freopen (const char * const path, const char * const mode, FILE* stream)
{

	__lsr_main ();
# ifdef LSR_DEBUG
	printf ("libsecrm: freopen()\n");
	fflush (stdout);
# endif

	if ( __lsr_real_freopen == NULL ) {
# ifdef HAVE_ERRNO_H
		errno = ENOSYS;
# endif
		return NULL;
	}

	if ( (path == NULL) || (mode == NULL) || (stream == NULL) ) {
		return (*__lsr_real_freopen) ( path, mode, stream );
	}

	if ( (strlen (path) == 0) || (strlen (mode) == 0) ) {
		return (*__lsr_real_freopen) ( path, mode, stream );
	}

	if ( (strchr (mode, (int)'w') != NULL) || (strchr (mode, (int)'W') != NULL) ) {
		fflush (stream);
		rewind (stream);
		truncate (path, 0);
	}

	return (*__lsr_real_freopen) ( path, mode, stream );
}
#endif /* __USE_LARGEFILE64 */

/* ======================================================= */

/* 'man 2 open' gives:
    int open(const char *pathname, int flags);
    int open(const char *pathname, int flags, mode_t mode);
   'man 3p open' (POSIX) & /usr/include/fcntl.h give:
    int open(const char *path, int oflag, ...  );
 */

#ifdef __USE_LARGEFILE64
int
open64 (const char * const path, const int flags, ... )
{

	va_list args;
	int ret_fd, mode, err;

	__lsr_main ();
# ifdef LSR_DEBUG
	printf ("libsecrm: open64()\n");
	fflush (stdout);
# endif

	if ( __lsr_real_open64 == NULL ) {
# ifdef HAVE_ERRNO_H
		errno = ENOSYS;
# endif
		return -1;
	}

	va_start (args, flags);
	mode = va_arg (args, int);

	if ( path == NULL ) {
		ret_fd = (*__lsr_real_open64) ( path, flags, mode );
		va_end (args);
		return ret_fd;
	}

	if ( strlen (path) == 0 ) {
		ret_fd = (*__lsr_real_open64) ( path, flags, mode );
		va_end (args);
		return ret_fd;
	}

	if ( ((flags & O_TRUNC) == O_TRUNC)
		&& (
		((flags & O_WRONLY) == O_WRONLY) || ((flags & O_RDWR) == O_RDWR)
		)
	) {
		truncate64 (path, (off64_t)0);
	}

#ifdef HAVE_ERRNO_H
	errno = 0;
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
#else /* __USE_LARGEFILE64 */

/* ======================================================= */

int
open (const char * const path, const int flags, ... )
{

	va_list args;
	int ret_fd, mode, err;

	__lsr_main ();
# ifdef LSR_DEBUG
	printf ("libsecrm: open()\n");
	fflush (stdout);
# endif

	if ( __lsr_real_open == NULL ) {
# ifdef HAVE_ERRNO_H
		errno = ENOSYS;
# endif
		return -1;
	}

	va_start (args, flags);
	mode = va_arg (args, int);

	if ( path == NULL ) {
		ret_fd = (*__lsr_real_open) ( path, flags, mode );
		va_end (args);
		return ret_fd;
	}

	if ( strlen (path) == 0 ) {
		ret_fd = (*__lsr_real_open) ( path, flags, mode );
		va_end (args);
		return ret_fd;
	}

	if ( ((flags & O_TRUNC) == O_TRUNC)
		&& (
		((flags & O_WRONLY) == O_WRONLY) || ((flags & O_RDWR) == O_RDWR)
		)
	) {
		truncate (path, 0);
	}

#ifdef HAVE_ERRNO_H
	errno = 0;
#endif
	ret_fd = (*__lsr_real_open) ( path, flags, mode );
#ifdef HAVE_ERRNO_H
	err = errno;
#endif
	va_end (args);
#ifdef HAVE_ERRNO_H
	errno = err;
#endif

	return ret_fd;
}
#endif	/* __USE_LARGEFILE64 */

/* ======================================================= */

FILE*
fdopen (const int filedes, const char * const mode)
{

	__lsr_main ();
#ifdef LSR_DEBUG
	printf ("libsecrm: fdopen()\n");
	fflush (stdout);
#endif

	if ( __lsr_real_fdopen == NULL ) {
#ifdef HAVE_ERRNO_H
		errno = ENOSYS;
#endif
		return NULL;
	}

	if ( mode == NULL ) {
		return (*__lsr_real_fdopen) ( filedes, mode );
	}

	if ( strlen (mode) == 0 ) {
		return (*__lsr_real_fdopen) ( filedes, mode );
	}

	if ( (strchr (mode, (int)'w') != NULL) || (strchr (mode, (int)'W') != NULL) ) {
#ifdef __USE_FILE_OFFSET64
		ftruncate64 (filedes, (off64_t)0);
#else
		ftruncate (filedes, 0);
#endif
	}

	return (*__lsr_real_fdopen) ( filedes, mode );
}

/* ======================================================= */

#ifdef __USE_LARGEFILE64
int
openat64 (const int dirfd, const char * const pathname, const int flags, ...)
{

	int fd, ret_fd, mode, err;
	va_list args;

	__lsr_main ();

# ifdef LSR_DEBUG
	printf ("libsecrm: openat64()\n");
	fflush (stdout);
# endif

	if ( __lsr_real_openat64 == NULL ) {
# ifdef HAVE_ERRNO_H
		errno = ENOSYS;
# endif
		return -1;
	}

	va_start (args, flags);
	mode = va_arg (args, int);

	if ( pathname == NULL ) {
		ret_fd = (*__lsr_real_openat64) ( dirfd, pathname, flags, mode );
		va_end (args);
		return ret_fd;
	}

	if ( strlen (pathname) == 0 ) {
		ret_fd = (*__lsr_real_openat64) ( dirfd, pathname, flags, mode );
		va_end (args);
		return ret_fd;
	}

	if ( ((flags & O_TRUNC) == O_TRUNC)
		&& (
		((flags & O_WRONLY) == O_WRONLY) || ((flags & O_RDWR) == O_RDWR)
		)
	) {


# ifdef HAVE_ERRNO_H
		errno = 0;
# endif
		fd = (*__lsr_real_openat64) (dirfd, pathname, O_RDWR, S_IRUSR|S_IWUSR);
		if ( (fd >= 0)
# ifdef HAVE_ERRNO_H
			|| (errno == 0)
# endif
		) {
			ftruncate64 (fd, (off64_t)0);
			close (fd);
		}
	}
#ifdef HAVE_ERRNO_H
	errno = 0;
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
#else	/* __USE_LARGEFILE64 */


/* ======================================================= */

/*
int openat(int dirfd, const char *pathname, int flags);
int openat(int dirfd, const char *pathname, int flags, mode_t mode);
 */

int
openat (const int dirfd, const char * const pathname, const int flags, ...)
{

	int fd, ret_fd, mode, err;
	va_list args;

	__lsr_main ();

# ifdef LSR_DEBUG
	printf ("libsecrm: openat()\n");
	fflush (stdout);
# endif

	if ( __lsr_real_openat == NULL ) {
# ifdef HAVE_ERRNO_H
		errno = ENOSYS;
# endif
		return -1;
	}

	va_start (args, flags);
	mode = va_arg (args, int);

	if ( pathname == NULL ) {
		ret_fd = (*__lsr_real_openat) ( dirfd, pathname, flags, mode );
		va_end (args);
		return ret_fd;
	}

	if ( strlen (pathname) == 0 ) {
		ret_fd = (*__lsr_real_openat) ( dirfd, pathname, flags, mode );
		va_end (args);
		return ret_fd;
	}

	if ( ((flags & O_TRUNC) == O_TRUNC)
		&& (
		((flags & O_WRONLY) == O_WRONLY) || ((flags & O_RDWR) == O_RDWR)
		)
	) {


# ifdef HAVE_ERRNO_H
		errno = 0;
# endif
		fd = (*__lsr_real_openat) (dirfd, pathname, O_RDWR, S_IRUSR|S_IWUSR);
		if ( (fd >= 0)
# ifdef HAVE_ERRNO_H
			|| (errno == 0)
# endif
		) {
			ftruncate (fd, 0);
			close (fd);
		}
	}
#ifdef HAVE_ERRNO_H
	errno = 0;
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
#endif /* __USE_LARGEFILE64 */
