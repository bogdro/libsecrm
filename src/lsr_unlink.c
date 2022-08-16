/*
 * A library for secure removing files.
 *	-- file deleting (removing, unlinking) functions' replacements.
 *
 * Copyright (C) 2007-2019 Bogdan Drozdowski, bogdandr (at) op.pl
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
#define _ATFILE_SOURCE 1

#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#else
# define O_WRONLY	1
# define O_RDWR		2
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

#ifdef LSR_DEBUG
# include <stdio.h>
#endif

#ifdef HAVE_MALLOC_H
# include <malloc.h>
#endif

#ifdef HAVE_STDLIB_H
# include <stdlib.h>	/* random(), rand()  */
#endif

#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif

#ifdef HAVE_LIBGEN_H
# include <libgen.h>
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>	/* rmdir() */
#endif

#include "lsr_priv.h"

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

#ifdef HAVE_RENAMEAT
# define LSR_ONLY_WITH_RENAMEAT
#else
# define LSR_ONLY_WITH_RENAMEAT LSR_ATTR ((unused))
#endif

/* ======================================================= */
#ifdef HAVE_MALLOC
/**
 * Renames the given file using rename() or renameat(). The return value is
 * the "last new name" and MUST be free()d unless *free_new == 0.
 */
# ifndef LSR_ANSIC
static char * __lsr_rename LSR_PARAMS((const char * const name,
	const int use_renameat, const int renameat_fd, int * const free_new));
# endif

static char *
# ifdef LSR_ANSIC
LSR_ATTR ((nonnull))
# endif
__lsr_rename (
# ifdef LSR_ANSIC
	const char * const name,
	const int use_renameat LSR_ONLY_WITH_RENAMEAT,
	const int renameat_fd LSR_ONLY_WITH_RENAMEAT,
	int * const free_new )
# else
	name, use_renameat, renameat_fd, free_new )
	const char * const name;
	const int use_renameat LSR_ONLY_WITH_RENAMEAT;
	const int renameat_fd LSR_ONLY_WITH_RENAMEAT;
	int * const free_new;
# endif
{
	char *old_name, *new_name;
	const char *base_name;
	unsigned int i, j, rnd;
	unsigned long int diff;
	size_t base_len;
	size_t name_len;
	char repl;
	int rename_res;

	if ( free_new != NULL )
	{
		*free_new = 0;
	}
	if ( name == NULL )
	{
		return NULL;
	}

	name_len = strlen (name);
	new_name = (char *) malloc ( name_len + 1 );
	if ( new_name == NULL )
	{
		return NULL;
	}

	old_name = (char *) malloc ( name_len + 1 );
	if ( old_name == NULL )
	{
		free (new_name);
		return NULL;
	}
	if ( free_new != NULL )
	{
		*free_new = 1;
	}
	__lsr_copy_string (new_name, name, name_len);

# if (defined HAVE_LIBGEN_H) && (defined HAVE_BASENAME)
	base_name = strstr ( name, basename (new_name) );
	/* basename() may modify its parameter, so set it back again. */
	__lsr_copy_string (new_name, name, name_len);
# else /* ! ((defined HAVE_LIBGEN_H) && (defined HAVE_BASENAME)) */
	base_name = strrchr (name, (int)'/'); /*rindex (name, (int)'/');*/
# endif
	if ( base_name == NULL )
	{
		base_len = name_len;
		base_name = name;
	}
	else
	{
		base_len = strlen (base_name);
	}
	old_name[name_len] = '\0';

	diff = name_len - base_len;
	for ( i = 0; i < __lsr_get_npasses (); i++ )
	{
# if (!defined __STRICT_ANSI__) && (defined HAVE_RANDOM)
		rnd = (unsigned int) random ();
# else
		rnd = (unsigned int) rand ();
# endif
		repl = (char) ('A' + (rnd % 26));
		__lsr_copy_string (old_name, new_name, name_len);

		for ( j = 0; j < base_len; j++ )
		{
			new_name[j+diff] = repl;
		}
		rename_res = 0;
# ifdef HAVE_RENAMEAT
		if ( (use_renameat != 0) && (renameat_fd >= 0) )
		{
			rename_res = renameat (renameat_fd, old_name,
				renameat_fd, new_name);
		}
		else
# endif
		{
			rename_res = rename (old_name, new_name);
		}
		if ( rename_res != 0 )
		{
			/* Rename failed - restore the original name.
			Re-trying could lead to the same errors again
			and to an infinite loop. */
			__lsr_copy_string (new_name, old_name, name_len);
			continue;
		}

# if (!defined __STRICT_ANSI__) && (defined HAVE_UNISTD_H)
		if ( __lsr_get_npasses () > 1 )
		{
			sync();
		}
# endif
	}
	free (old_name);
	return new_name;
}
#endif /* HAVE_MALLOC */

/* ======================================================= */

int
unlink (
#ifdef LSR_ANSIC
	const char * const name)
#else
	name)
	const char * const name;
#endif
{
#if (defined __GNUC__) && (!defined unlink)
# pragma GCC poison unlink
#endif
	int free_new, fd, res;
	char *new_name = NULL;
	LSR_MAKE_ERRNO_VAR(err);

	__lsr_main ();
#ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: unlink(%s)\n", (name==NULL)? "null" : name);
	fflush (stderr);
#endif
	if ( __lsr_real_unlink_location () == NULL )
	{
		LSR_SET_ERRNO_MISSING();
		return -1;
	}

	if ( __lsr_can_wipe_filename (name, 0) == 0 )
	{
		LSR_SET_ERRNO (err);
		return (*__lsr_real_unlink_location ()) (name);
	}

	if ( __lsr_real_open_location () != NULL )
	{
		fd = (*__lsr_real_open_location ()) (name, O_WRONLY|O_EXCL);
		if ( fd >= 0 )
		{
#ifdef LSR_DEBUG
			fprintf (stderr, "libsecrm: unlink(): wiping %s\n", name);
			fflush (stderr);
#endif
			__lsr_fd_truncate ( fd, (off64_t)0 );
			close (fd);
		}
	}

	free_new = 0;
#ifdef HAVE_MALLOC
	new_name = __lsr_rename ( name, 0, -1, &free_new );
#endif

	if ( new_name == NULL )
	{
		res = (*__lsr_real_unlink_location ()) (name);
		LSR_GET_ERRNO(err);
	}
#ifdef HAVE_MALLOC
	else
	{
		res = (*__lsr_real_unlink_location ()) (new_name);
		LSR_GET_ERRNO(err);
		if ( res != 0 )
		{
			rename (new_name, name);
		}
	}
	if ( (free_new != 0) && (new_name != NULL) )
	{
		free (new_name);
	}

#endif /* HAVE_MALLOC */
	LSR_SET_ERRNO (err);

	return res;
}

/* ======================================================= */

int
unlinkat (
#ifdef LSR_ANSIC
	const int dirfd, const char * const name, const int flags)
#else
	dirfd, name, flags)
	const int dirfd;
	const char * const name;
	const int flags;
#endif
{
#if (defined __GNUC__) && (!defined unlinkat)
# pragma GCC poison unlinkat
#endif
	int free_new, fd, res;
	char *new_name = NULL;
	LSR_MAKE_ERRNO_VAR(err);

	__lsr_main ();
#ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: unlinkat(%d, %s, %d)\n", dirfd,
		(name==NULL)? "null" : name, flags);
	fflush (stderr);
#endif

	if ( __lsr_real_unlinkat_location () == NULL )
	{
		LSR_SET_ERRNO_MISSING();
		return -1;
	}

	if ( __lsr_can_wipe_filename_atdir (name, dirfd, 0) == 0 )
	{
		LSR_SET_ERRNO (err);
		return (*__lsr_real_unlinkat_location ()) (dirfd, name, flags);
	}

	if ( __lsr_real_openat_location () != NULL )
	{
		fd = (*__lsr_real_openat_location ()) (dirfd, name, O_WRONLY);
		if ( fd >= 0 )
		{
#ifdef LSR_DEBUG
			fprintf (stderr, "libsecrm: unlinkat(): wiping %s\n", name);
			fflush (stderr);
#endif

			__lsr_fd_truncate ( fd, (off64_t)0 );
#ifdef HAVE_UNISTD_H
			close (fd);
#endif
		}
	}

	free_new = 0;
#ifdef HAVE_MALLOC
	new_name = __lsr_rename ( name, 1, dirfd, &free_new );
#endif
	if ( new_name == NULL )
	{
		res = (*__lsr_real_unlinkat_location ()) (dirfd, name, flags);
		LSR_GET_ERRNO(err);
	}
#ifdef HAVE_MALLOC
	else
	{
		res = (*__lsr_real_unlinkat_location ()) (dirfd, new_name, flags);
		LSR_GET_ERRNO(err);
# ifdef HAVE_RENAMEAT
		if ( res != 0 )
		{
			renameat (dirfd, new_name, dirfd, name);
		}
# endif
	}
	if ( (free_new != 0) && (new_name != NULL) )
	{
		free (new_name);
	}
#endif /* HAVE_MALLOC */
	LSR_SET_ERRNO (err);

	return res;
}

/* ======================================================= */

int
remove (
#ifdef LSR_ANSIC
	const char * const name)
#else
	name)
	const char * const name;
#endif
{
#if (defined __GNUC__) && (!defined remove)
# pragma GCC poison remove
#endif

	int free_new, fd, res;
	char *new_name = NULL;
	LSR_MAKE_ERRNO_VAR(err);

	__lsr_main ();
#ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: remove(%s)\n",
		(name==NULL)? "null" : name);
	fflush (stderr);
#endif

	if ( __lsr_real_remove_location () == NULL )
	{
		LSR_SET_ERRNO_MISSING();
		return -1;
	}

	if ( __lsr_can_wipe_filename (name, 0) == 0 )
	{
		LSR_SET_ERRNO (err);
		return (*__lsr_real_remove_location ()) (name);
	}

	if ( __lsr_real_open_location () != NULL )
	{
		fd = (*__lsr_real_open_location ()) (name, O_WRONLY | O_EXCL);
		if ( fd >= 0 )
		{
#ifdef LSR_DEBUG
			fprintf (stderr, "libsecrm: remove(): wiping %s\n", name);
			fflush (stderr);
#endif
			__lsr_fd_truncate ( fd, (off64_t)0 );
			close (fd);
		}	/* fd >= 0 */
	} /* __real_open */

	free_new = 0;
#ifdef HAVE_MALLOC
	new_name = __lsr_rename ( name, 0, -1, &free_new );
#endif

	if ( new_name == NULL )
	{
		res = (*__lsr_real_remove_location ()) (name);
		LSR_GET_ERRNO(err);
	}
#ifdef HAVE_MALLOC
	else
	{
		res = (*__lsr_real_remove_location ()) (new_name);
		LSR_GET_ERRNO(err);
		if ( res != 0 )
		{
			rename (new_name, name);
		}
	}
	if ( (free_new != 0) && (new_name != NULL) )
	{
		free (new_name);
	}
#endif /* HAVE_MALLOC */
	LSR_SET_ERRNO (err);

	return res;
}

/* ======================================================= */

int
rmdir (
#ifdef LSR_ANSIC
	const char * const name)
#else
	name)
	const char * const name;
#endif
{
#if (defined __GNUC__) && (!defined rmdir)
# pragma GCC poison rmdir
#endif

	int free_new, res;
	char *new_name = NULL;
#ifdef HAVE_SYS_STAT_H
	struct stat s;
#endif
	LSR_MAKE_ERRNO_VAR(err);

	__lsr_main ();
#ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: rmdir(%s)\n",
		(name==NULL)? "null" : name);
	fflush (stderr);
#endif

	if ( __lsr_real_rmdir_location () == NULL )
	{
		LSR_SET_ERRNO_MISSING();
		return -1;
	}

	if ( name == NULL )
	{
		LSR_SET_ERRNO (err);
		return (*__lsr_real_rmdir_location ()) (name);
	}

	if ( name[0] == '\0' /*strlen (name) == 0*/ )
	{
		LSR_SET_ERRNO (err);
		return (*__lsr_real_rmdir_location ()) (name);
	}

#if (!defined HAVE_SYS_STAT_H) || (!defined HAVE_LSTAT)
	/* Sorry, can't truncate something I can't lstat().
	   This would cause problems. */
	LSR_SET_ERRNO (err);
	return (*__lsr_real_rmdir_location ()) (name);
#else
	if ( lstat (name, &s) == 0 )
	{
		/* don't operate on non-directories */
		if ( !S_ISDIR (s.st_mode) )
		{
			LSR_SET_ERRNO (err);
			return (*__lsr_real_rmdir_location ()) (name);
		}
	}
	else
	{
		LSR_SET_ERRNO (err);
		return (*__lsr_real_rmdir_location ()) (name);
	}

	if ( __lsr_can_wipe_dirname (name) == 0 )
	{
		LSR_SET_ERRNO (err);
		return (*__lsr_real_rmdir_location ()) (name);
	}

	free_new = 0;
# ifdef HAVE_MALLOC
	new_name = __lsr_rename ( name, 0, -1, &free_new );
# endif

	if ( new_name == NULL )
	{
		res = (*__lsr_real_rmdir_location ()) (name);
		LSR_GET_ERRNO(err);
	}
# ifdef HAVE_MALLOC
	else
	{
		res = (*__lsr_real_rmdir_location ()) (new_name);
		LSR_GET_ERRNO(err);
		if ( res != 0 )
		{
			rename (new_name, name);
		}
	}
	if ( (free_new != 0) && (new_name != NULL) )
	{
		free (new_name);
	}
# endif /* HAVE_MALLOC */
	LSR_SET_ERRNO (err);

	return res;

#endif	/* stat.h */
}
