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

#if (!defined __USE_FILE_OFFSET64) && (!defined __USE_LARGEFILE64)
# define fopen64 fopen
# define open64 open
# define freopen64 freopen
# define creat64 creat
# define truncate64 truncate
# define ftruncate64 ftruncate
#endif

extern int openat(int dirfd, const char *pathname, int flags, mode_t mode);
extern int openat64(int dirfd, const char *pathname, int flags, mode_t mode);
extern int unlinkat(int dirfd, const char *pathname, int flags);

FILE*
lsr_fopen64 (const char * const name, const char * const mode)
{
	return fopen64 (name, mode);
}

FILE*
lsr_fopen (const char * const name, const char * const mode)
{
	return fopen (name, mode);
}

FILE*
lsr_freopen64 (const char * const path, const char * const mode, FILE* stream)
{
	return freopen64 (path, mode, stream);
}

FILE*
lsr_freopen (const char * const name, const char * const mode, FILE* stream)
{
	return freopen (name, mode, stream);
}

int
lsr_open64 (const char * const path, const int flags, ... )
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
lsr_open (const char * const path, const int flags, ... )
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
lsr_openat64 (const int dirfd, const char * const path, const int flags, ...)
{
	va_list args;
	int ret_fd;
	mode_t mode;

	va_start (args, flags);
	mode = va_arg (args, int);

	ret_fd = openat64 (dirfd, path, flags, mode);
	va_end (args);
	return ret_fd;
}

int
lsr_openat (const int dirfd, const char * const path, const int flags, ...)
{
	va_list args;
	int ret_fd;
	mode_t mode;

	va_start (args, flags);
	mode = va_arg (args, int);

	ret_fd = openat (dirfd, path, flags, mode);
	va_end (args);
	return ret_fd;
}

int
lsr_truncate (const char * const path, const off_t length)
{
	return truncate (path, length);
}

int
lsr_truncate64 (const char * const path, const off64_t length)
{
	return truncate64 (path, length);
}

int
lsr_ftruncate (int fd, const off_t length)
{
	return ftruncate (fd, length);
}

int
lsr_ftruncate64 (int fd, const off64_t length)
{
	return ftruncate64 (fd, length);
}

int
lsr_unlink (const char * const name)
{
	return unlink (name);
}

int
lsr_unlinkat (const int dirfd, const char * const name, const int flags)
{
	return unlinkat (dirfd, name, flags);
}

int
lsr_remove (const char * const name)
{
	return remove (name);
}

int
lsr_creat64 (const char * const path, const mode_t mode )
{
	return creat64 (path, mode);
}

int
lsr_creat (const char * const path, const mode_t mode )
{
	return creat (path, mode);
}

