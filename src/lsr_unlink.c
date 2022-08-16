/*
 * A library for secure removing files.
 *	-- file deleting (removing, unlinking) functions' replacements.
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

#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#else
# define O_WRONLY	1
# define O_RDWR		2
#endif

#ifdef HAVE_STRING_H
# if (!STDC_HEADERS) && (defined HAVE_MEMORY_H)
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

#ifdef __GNUC__
# pragma GCC poison fopen open freopen fdopen openat open64 fopen64 freopen64 openat64
#endif

/* ======================================================= */
/**
 * Renames the given file using rename() or renameat(). The return value is
 * the "last new name" and MUST be free()d unless *free_new == 0.
 */
static char * LSR_ATTR ((nonnull))
__lsr_rename (  const char * const name, const int use_renameat, const int renameat_fd,
		int * const free_new )
{

	char *old_name, *new_name;
	const char *base_name;
	unsigned int i, j, rnd;
	int diff;
	size_t base_len, name_len;
	char repl;

	*free_new = 0;
	name_len = strlen (name);
	new_name = (char *) malloc ( name_len + 1 );
	if ( new_name == NULL )
	{
		return name;
	}

	old_name = (char *) malloc ( name_len + 1 );
	if ( old_name == NULL )
	{
		free (new_name);
		return name;
	}
	*free_new = 1;
#ifdef HAVE_STRING_H
	strncpy (new_name, name, name_len);
#elif defined HAVE_MEMCPY
	memcpy (new_name, name, name_len);
#else
	for ( i=0; i < name_len; i++ )
	{
		new_name[i] = name[i];
	}
#endif
	new_name[name_len] = '\0';

#ifdef HAVE_LIBGEN_H
	base_name = strstr ( name, basename (new_name) );
	/* basename() may modify its parameter, so set it back again. */
# ifdef HAVE_STRING_H
	strncpy (new_name, name, name_len);
# elif defined HAVE_MEMCPY
	memcpy (new_name, name, name_len);
# else
	for ( i=0; i < name_len; i++ )
	{
		new_name[i] = name[i];
	}
# endif
	new_name[name_len] = '\0';
#else
	base_name = rindex ( name, (int)'/' );
#endif
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
	for ( i=0; i < npasses; i++ )
	{
#if (!defined __STRICT_ANSI__) && (defined HAVE_RANDOM)
		rnd = (unsigned) random ();
#else
		rnd = (unsigned) rand ();
#endif
		repl = (char) ('A'+(rnd%26));
#ifdef HAVE_STRING_H
		strncpy (old_name, new_name, name_len);
#elif defined HAVE_MEMCPY
		memcpy (old_name, new_name, name_len);
#else
		for ( i=0; i < name_len; i++ )
		{
			old_name[i] = new_name[i];
		}
#endif

		for ( j=0; j < base_len; j++ )
		{
			new_name[j+diff] = repl;
		}

		if ( (use_renameat != 0) && (renameat_fd > 0) )
		{
			renameat ( renameat_fd, old_name, renameat_fd, new_name );
		}
		else
		{
			rename (old_name, new_name);
		}
	}
	free (old_name);
	return new_name;
}

/* ======================================================= */

int
unlink ( const char * const name )
{
	int res, free_new;
	char *new_name;

#ifdef HAVE_SYS_STAT_H
# ifndef LSR_USE64
	struct stat s;
# else
	struct stat64 s;
# endif
#endif

#ifdef HAVE_ERRNO_H
	int err = 0;
#endif

	__lsr_main ();
#ifdef LSR_DEBUG
	printf ("libsecrm: unlink(%s)\n", (name==NULL)? "null" : name);
	fflush (stdout);
#endif

	if ( __lsr_real_unlink == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = ENOSYS;
#endif
		return -1;
	}

	if ( name == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_unlink) (name);
	}

	if ( (strlen (name) == 0) || (strstr(name, ".ICEauthority") != NULL) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_unlink) (name);
	}

#if (!defined HAVE_SYS_STAT_H) || (!defined HAVE_LSTAT)
	/* Sorry, can't truncate something I can't lstat(). This would cause problems *
	new_name = __lsr_rename ( name, 0, -1, &free_new );
# ifdef HAVE_ERRNO_H
	errno = err;
# endif
	res = (*__lsr_real_unlink) (new_name);
# ifdef HAVE_ERRNO_H
	err = errno;
# endif
	if ( free_new != 0 )
	{
		free (new_name);
	}
# ifdef HAVE_ERRNO_H
	errno = err;
# endif
	return res;
	*/
# ifdef HAVE_ERRNO_H
	errno = err;
# endif
	return (*__lsr_real_unlink) (name);
#else

	/* NOTE: stat() may be dangerous. If a filesystem has symbolic links, but lstat()
	   is unavailable, stat() returns information about the target of the link.
	   The link itself will be removed, but it's the target of the link
	   that will be wiped. This is why we either use lstat() or quit.
	*/
# ifndef LSR_USE64
	if ( lstat (name, &s) == 0 )
# else
	if ( lstat64 (name, &s) == 0 )
# endif
	{
		/* don't operate on non-files */
		if ( !S_ISREG (s.st_mode) )
		{
			/* NOTE: old name may be needed.
			new_name = __lsr_rename ( name, 0, -1, &free_new );
# ifdef HAVE_ERRNO_H
			errno = err;
# endif
			res = (*__lsr_real_unlink) (new_name);
# ifdef HAVE_ERRNO_H
			err = errno;
# endif
			if ( free_new != 0 )
			{
				free (new_name);
			}
# ifdef HAVE_ERRNO_H
			errno = err;
# endif
			return res;
			*/
# ifdef HAVE_ERRNO_H
			errno = err;
# endif
			return (*__lsr_real_unlink) (name);
		}
	}
	else
	{
		/*
		new_name = __lsr_rename ( name, 0, -1, &free_new );
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		res = (*__lsr_real_unlink) (new_name);
# ifdef HAVE_ERRNO_H
		err = errno;
# endif
		if ( free_new != 0 )
		{
			free (new_name);
		}
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		return res;
		*/
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		return (*__lsr_real_unlink) (name);
	}

# ifdef LSR_USE64
	truncate64 (name, 0LL);
# else
	truncate (name, 0);
# endif

	new_name = __lsr_rename ( name, 0, -1, &free_new );

# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	res = (*__lsr_real_unlink) (new_name);
# ifdef HAVE_ERRNO_H
	err = errno;
# endif
	if ( free_new != 0 )
	{
		free (new_name);
	}
# ifdef HAVE_ERRNO_H
	errno = err;
# endif
	return res;

#endif	/* stat.h */
}

/* ======================================================= */

int
unlinkat (const int dirfd, const char * const pathname, const int flags)
{
#ifdef __GNUC__
# pragma GCC poison unlinkat
#endif

	int fd, res, free_new;
	char *new_name;

#ifdef HAVE_SYS_STAT_H
# ifndef LSR_USE64
	struct stat s;
# else
	struct stat64 s;
# endif
#endif

#ifdef HAVE_ERRNO_H
	int err = 0;
#endif

	__lsr_main ();
#ifdef LSR_DEBUG
	printf ("libsecrm: ulnikat(%d, %s, %d)\n", dirfd, (pathname==NULL)? "null" : pathname, flags);
	fflush (stdout);
#endif

	if ( __lsr_real_unlinkat == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = ENOSYS;
#endif
		return -1;
	}

	if ( pathname == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_unlinkat) (dirfd, pathname, flags);
	}

	if ( (strlen (pathname) == 0) || (strstr(pathname, ".ICEauthority") != NULL) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_unlinkat) (dirfd, pathname, flags);
	}

#ifdef HAVE_ERRNO_H
	errno = 0;
#endif
	fd = (*__lsr_real_openat) (dirfd, pathname, O_WRONLY);
	if ( (fd < 0)
#ifdef HAVE_ERRNO_H
		|| (errno != 0)
#endif
	   )
	{
		/*
		new_name = __lsr_rename ( pathname, 1, dirfd, &free_new );
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		res = (*__lsr_real_unlinkat) (dirfd, new_name, flags);
# ifdef HAVE_ERRNO_H
		err = errno;
# endif
		if ( free_new != 0 )
		{
			free (new_name);
		}
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return res;
		*/
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		return (*__lsr_real_unlinkat) (dirfd, pathname, flags);
	}

#if (!defined HAVE_SYS_STAT_H) || (!defined HAVE_FSTAT)
	/* Sorry, can't truncate something I can't stat. This would cause problems *
# ifdef HAVE_UNISTD_H
	close (fd);
# endif
	new_name = __lsr_rename ( pathname, 1, dirfd, &free_new );
# ifdef HAVE_ERRNO_H
	errno = err;
# endif
	res = (*__lsr_real_unlinkat) (dirfd, new_name, flags);
# ifdef HAVE_ERRNO_H
	err = errno;
# endif
	if ( free_new != 0 )
	{
		free (new_name);
	}
# ifdef HAVE_ERRNO_H
	errno = err;
# endif
	return res;
	*/
	close (fd);
# ifdef HAVE_ERRNO_H
	errno = err;
# endif
	return (*__lsr_real_unlinkat) (dirfd, pathname, flags);
#else
# ifndef LSR_USE64
	if ( fstat (fd, &s) == 0 )
# else
	if ( fstat64 (fd, &s) == 0 )
# endif
	{
		/* don't operate on non-files */
		if ( !S_ISREG (s.st_mode) )
		{
			/*
# ifdef HAVE_UNISTD_H
			close (fd);
# endif
			new_name = __lsr_rename ( pathname, 1, dirfd, &free_new );
# ifdef HAVE_ERRNO_H
			errno = err;
# endif
			res = (*__lsr_real_unlinkat) (dirfd, new_name, flags);
# ifdef HAVE_ERRNO_H
			err = errno;
# endif
			if ( free_new != 0 )
			{
				free (new_name);
			}
# ifdef HAVE_ERRNO_H
			errno = err;
# endif
			return res;
			*/
# ifdef HAVE_ERRNO_H
			errno = err;
# endif
			return (*__lsr_real_unlinkat) (dirfd, pathname, flags);
		}
	}
	else
	{
		/*
# ifdef HAVE_UNISTD_H
		close (fd);
# endif
		new_name = __lsr_rename ( pathname, 1, dirfd, &free_new );
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		res = (*__lsr_real_unlinkat) (dirfd, new_name, flags);
# ifdef HAVE_ERRNO_H
		err = errno;
# endif
		if ( free_new != 0 )
		{
			free (new_name);
		}
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		return res;
		*/
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		return (*__lsr_real_unlinkat) (dirfd, pathname, flags);
	}

# ifdef LSR_USE64
	ftruncate64 (fd, 0LL);
# else
	ftruncate (fd, 0);
# endif

# ifdef HAVE_UNISTD_H
	close (fd);
# endif

	new_name = __lsr_rename ( pathname, 1, dirfd, &free_new );

# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	res = (*__lsr_real_unlinkat) (dirfd, new_name, flags);
# ifdef HAVE_ERRNO_H
	err = errno;
# endif
	if ( free_new != 0 )
	{
		free (new_name);
	}
# ifdef HAVE_ERRNO_H
	errno = err;
# endif
	return res;

#endif	/* stat.h */
}

/* ======================================================= */

int
remove ( const char * const name )
{
#ifdef __GNUC__
# pragma GCC poison remove
#endif

	int res, free_new;
	char *new_name;

#ifdef HAVE_SYS_STAT_H
# ifndef LSR_USE64
	struct stat s;
# else
	struct stat64 s;
# endif
#endif

#ifdef HAVE_ERRNO_H
	int err = 0;
#endif

	__lsr_main ();
#ifdef LSR_DEBUG
	printf ("libsecrm: remove(%s)\n", (name==NULL)? "null" : name);
	fflush (stdout);
#endif

	if ( __lsr_real_remove == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = ENOSYS;
#endif
		return -1;
	}

	if ( name == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_remove) (name);
	}

	if ( (strlen (name) == 0) || (strstr(name, ".ICEauthority") != NULL) )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_remove) (name);
	}

#if (!defined HAVE_SYS_STAT_H) || (!defined HAVE_LSTAT)
	/* Sorry, can't truncate something I can't lstat(). This would cause problems.
	   See unlink() above. *
# ifdef HAVE_ERRNO_H
	errno = err;
# endif
	new_name = __lsr_rename ( name, 0, -1, &free_new );
# ifdef HAVE_ERRNO_H
	errno = err;
# endif
	res = (*__lsr_real_remove) (new_name);
# ifdef HAVE_ERRNO_H
	err = errno;
# endif
	if ( free_new != 0 )
	{
		free (new_name);
	}
# ifdef HAVE_ERRNO_H
	errno = err;
# endif
	return res;
	*/
# ifdef HAVE_ERRNO_H
	errno = err;
# endif
	return (*__lsr_real_remove) (name);
#else
# ifndef LSR_USE64
	if ( lstat (name, &s) == 0 )
# else
	if ( lstat64 (name, &s) == 0 )
# endif
	{
		/* don't operate on non-files */
		if ( !S_ISREG (s.st_mode) )
		{
			/*
			new_name = __lsr_rename ( name, 0, -1, &free_new );
# ifdef HAVE_ERRNO_H
			errno = err;
# endif
			res = (*__lsr_real_remove) (new_name);
# ifdef HAVE_ERRNO_H
			err = errno;
# endif
			if ( free_new != 0 )
			{
				free (new_name);
			}
# ifdef HAVE_ERRNO_H
			errno = err;
# endif
			return res;
			*/
# ifdef HAVE_ERRNO_H
			errno = err;
# endif
			return (*__lsr_real_remove) (name);
		}
	}
	else
	{
		/*
		new_name = __lsr_rename ( name, 0, -1, &free_new );
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		res = (*__lsr_real_remove) (new_name);
# ifdef HAVE_ERRNO_H
		err = errno;
# endif
		if ( free_new != 0 )
		{
			free (new_name);
		}
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		return res;
		*/
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		return (*__lsr_real_remove) (name);
	}

# ifdef LSR_USE64
	truncate64 (name, 0LL);
# else
	truncate (name, 0);
# endif

	new_name = __lsr_rename ( name, 0, -1, &free_new );

# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	res = (*__lsr_real_remove) (new_name);
# ifdef HAVE_ERRNO_H
	err = errno;
# endif
	if ( free_new != 0 )
	{
		free (new_name);
	}
# ifdef HAVE_ERRNO_H
	errno = err;
# endif
	return res;

#endif	/* stat.h */
}
