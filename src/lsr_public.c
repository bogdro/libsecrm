/*
 * A library for secure removing files.
 *	-- public interface file
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
#include "libsecrm.h"

#include <stdio.h>

#ifdef HAVE_STDARG_H
# include <stdarg.h>
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif

#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif

#undef LSR_ATTR
#ifdef __GNUC__
# define LSR_ATTR(x)	__attribute__(x)
#else
# define LSR_ATTR(x)
#endif


#if (!defined __USE_FILE_OFFSET64) && (!defined __USE_LARGEFILE64)
# define fopen64 fopen
# define open64 open
# define freopen64 freopen
# define creat64 creat
# define truncate64 truncate
# define ftruncate64 ftruncate
#endif

#ifdef HAVE_OPENAT
extern int openat (int dirfd, const char *pathname, int flags, ...);
extern int openat64 (int dirfd, const char *pathname, int flags, ...);
#endif
#ifdef HAVE_UNLINKAT
extern int unlinkat (int dirfd, const char *pathname, int flags);
#endif

FILE*
lsr_fopen64 (
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
	return fopen64 (name, mode);
}

FILE*
lsr_fopen (
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
	return fopen (name, mode);
}

FILE*
lsr_freopen64 (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	const char * const path, const char * const mode, FILE* stream)
#else
	path, mode, stream)
	const char * const path;
	const char * const mode;
	FILE* stream;
#endif
{
	return freopen64 (path, mode, stream);
}

FILE*
lsr_freopen (
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
	return freopen (name, mode, stream);
}

int
lsr_open64 (
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
	va_list args;
	int ret_fd;
	mode_t mode;

	va_start (args, flags);
	mode = va_arg (args, int);

	ret_fd = open64 (path, flags, mode);
	va_end (args);
	return ret_fd;
}

int
lsr_open (
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
	va_list args;
	int ret_fd;
	mode_t mode;

	va_start (args, flags);
	mode = va_arg (args, int);

	ret_fd = open (path, flags, mode);
	va_end (args);
	return ret_fd;
}

int
lsr_openat64 (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	const int dirfd
# ifndef HAVE_OPENAT
	LSR_ATTR((unused))
# endif
	, const char * const path
# ifndef HAVE_OPENAT
	LSR_ATTR((unused))
# endif
	, const int flags
# ifndef HAVE_OPENAT
	LSR_ATTR((unused))
# endif
	, ...)
#else
	dirfd, path, flags, ...)
	const int dirfd;
	const char * const path;
	const int flags;
#endif
{
#ifdef HAVE_OPENAT
	va_list args;
	int ret_fd;
	mode_t mode;

	va_start (args, flags);
	mode = va_arg (args, int);

	ret_fd = openat64 (dirfd, path, flags, mode);
	va_end (args);
	return ret_fd;
#else
# ifdef HAVE_ERRNO_H
	errno = -ENOSYS;
# endif
	return -1;
#endif
}

int
lsr_openat (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	const int dirfd
# ifndef HAVE_OPENAT
	LSR_ATTR((unused))
# endif
	, const char * const path
# ifndef HAVE_OPENAT
	LSR_ATTR((unused))
# endif
	, const int flags
# ifndef HAVE_OPENAT
	LSR_ATTR((unused))
# endif
	, ...)
#else
	dirfd, path, flags, ...)
	const int dirfd;
	const char * const path;
	const int flags;
#endif
{
#ifdef HAVE_OPENAT
	va_list args;
	int ret_fd;
	mode_t mode;

	va_start (args, flags);
	mode = va_arg (args, int);

	ret_fd = openat (dirfd, path, flags, mode);
	va_end (args);
	return ret_fd;
#else
# ifdef HAVE_ERRNO_H
	errno = -ENOSYS;
# endif
	return -1;
#endif /* HAVE_OPENAT */
}

int
lsr_truncate (
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
	return truncate (path, length);
}

int
lsr_truncate64 (
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
	return truncate64 (path, length);
}

int
lsr_ftruncate (
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
	return ftruncate (fd, length);
}

int
lsr_ftruncate64 (
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
	return ftruncate64 (fd, length);
}

int
lsr_unlink (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	const char * const name)
#else
	name)
	const char * const name;
#endif
{
	return unlink (name);
}

int
lsr_unlinkat (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	const int dirfd
# ifndef HAVE_UNLINKAT
	LSR_ATTR((unused))
# endif
	, const char * const name
# ifndef HAVE_UNLINKAT
	LSR_ATTR((unused))
# endif
	, const int flags
# ifndef HAVE_UNLINKAT
	LSR_ATTR((unused))
# endif
	)
#else
	dirfd, name, flags)
	const int dirfd;
	const char * const name;
	const int flags;
#endif
{
#ifdef HAVE_UNLINKAT
	return unlinkat (dirfd, name, flags);
#else
# ifdef HAVE_ERRNO_H
	errno = -ENOSYS;
# endif
	return -1;
#endif /* HAVE_UNLINKAT */
}

int
lsr_remove (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	const char * const name)
#else
	name)
	const char * const name;
#endif
{
	return remove (name);
}

int
lsr_creat64 (
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
	return creat64 (path, mode);
}

int
lsr_creat (
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
	return creat (path, mode);
}

