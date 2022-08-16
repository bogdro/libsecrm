/*
 * A library for secure removing files.
 *	-- file creation functions' replacements.
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

#define _LARGEFILE64_SOURCE 1

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

#include "lsr_priv.h"

/*
#ifndef HAVE_CREAT64
# ifdef __cplusplus
extern "C" {
# endif

extern int creat64 LSR_PARAMS((const char * const path, const mode_t mode));

# ifdef __cplusplus
}
# endif

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
#ifdef LSR_ANSIC
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

	LSR_MAKE_ERRNO_VAR(err);
	int fd;

	__lsr_main ();
#ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: creat64(%s, 0%o)\n", (path==NULL)? "null" : path, mode);
	fflush (stderr);
#endif

	if ( __lsr_real_creat64_location () == NULL )
	{
		LSR_SET_ERRNO_MISSING();
		return -1;
	}

	if ( __lsr_can_wipe_filename (path) == 0 )
	{
		LSR_SET_ERRNO (err);
		return (*__lsr_real_creat64_location ()) ( path, mode );
	}

	if ( __lsr_real_open64_location () != NULL )
	{
		fd = (*__lsr_real_open64_location ()) (path, O_WRONLY|O_EXCL);
		if ( fd >= 0 )
		{
			__lsr_fd_truncate ( fd, (off64_t)0 );
			close (fd);
		}
	}

	LSR_SET_ERRNO (err);
	return (*__lsr_real_creat64_location ()) ( path, mode );
}

/* ======================================================= */

#ifdef creat
# undef creat
#endif

int
creat (
#ifdef LSR_ANSIC
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
	LSR_MAKE_ERRNO_VAR(err);

	__lsr_main ();
#ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: creat(%s, 0%o)\n", (path==NULL)? "null" : path, mode);
	fflush (stderr);
#endif

	if ( __lsr_real_creat_location () == NULL )
	{
		LSR_SET_ERRNO_MISSING();
		return -1;
	}

	if ( __lsr_can_wipe_filename (path) == 0 )
	{
		LSR_SET_ERRNO (err);
		return (*__lsr_real_creat_location ()) ( path, mode );
	}

	if ( __lsr_real_open_location () != NULL )
	{
		fd = (*__lsr_real_open_location ()) (path, O_WRONLY|O_EXCL);
		if ( fd >= 0 )
		{
			__lsr_fd_truncate ( fd, (off64_t)0 );
			close (fd);
		}
	}

	LSR_SET_ERRNO (err);
	return (*__lsr_real_creat_location ()) ( path, mode );
}
