/*
 * A library for secure removing files.
 *	-- file deleting (removing, unlinking) functions' replacements.
 *
 * Copyright (C) 2007 Bogdan Drozdowski, bogdandr (at) op.pl
 * License: GNU General Public License, v2+
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
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
# define O_RDWR 2
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
# include <stdlib.h>	/* strtoul(), random(), srandom(), rand(), srand() */
#endif

/* ======================================================= */

int
unlink ( const char * const name )
{

	char *oldname, *newname;
	unsigned int i, j, rnd;
	int res;

	__lsr_main ();
#ifdef LSR_DEBUG
	printf ("libsecrm: unlink()\n");
	fflush (stdout);
#endif

	if ( __lsr_real_unlink == NULL ) {
#ifdef HAVE_ERRNO_H
		errno = ENOSYS;
#endif
		return -1;
	}

	if ( name == NULL ) {
		return (*__lsr_real_unlink) (name);
	}

	if ( strlen (name) == 0 ) {
		return (*__lsr_real_unlink) (name);
	}

#ifdef __USE_FILE_OFFSET64
	truncate (name, (off64_t)0);
#else
	truncate (name, 0);
#endif

	newname = (char *) malloc ( strlen (name) + 1 );
	oldname = (char *) malloc ( strlen (name) + 1 );
	strncpy (oldname, name, strlen (name) );
	for ( i=0; i < npasses; i++ ) {
		rnd = (unsigned) random ();
		for ( j=0; j < strlen (name); j++ ) {
			newname[j] = (char) ('A'+(rnd%26));
		}
		rename (oldname, newname );
		strncpy (oldname, newname, strlen (name) );
	}
	free (oldname);

	res = (*__lsr_real_unlink) (newname);
	free (newname);
	return res;
}

/* ======================================================= */

int
unlinkat (const int dirfd, const char * const pathname, const int flags)
{

	int fd, res;
	size_t len;
	char *oldname, *newname, *basename;
	unsigned int i, j, rnd;

	__lsr_main ();
#ifdef LSR_DEBUG
	printf ("libsecrm: ulnikat()\n");
	fflush (stdout);
#endif

	if ( __lsr_real_unlinkat == NULL ) {
#ifdef HAVE_ERRNO_H
		errno = ENOSYS;
#endif
		return -1;
	}

	if ( pathname == NULL ) {
		return (*__lsr_real_unlinkat) (dirfd, pathname, flags);
	}

	if ( strlen (pathname) == 0 ) {
		return (*__lsr_real_unlinkat) (dirfd, pathname, flags);
	}

#ifdef HAVE_ERRNO_H
	errno = 0;
#endif
	fd = (*__lsr_real_openat) (dirfd, pathname, O_RDWR);
	if ( (fd < 0)
#ifdef HAVE_ERRNO_H
		|| (errno != 0)
#endif
	) {
		return (*__lsr_real_unlinkat) (dirfd, pathname, flags);
	}

#ifdef __USE_FILE_OFFSET64
	ftruncate (fd, (off64_t)0);
#else
	ftruncate (fd, 0);
#endif
	close (fd);

	basename = rindex (pathname, (int) '/');
	if ( basename == NULL ) {
		len = strlen (pathname);
	} else {
		len = strlen (basename);
	}
	newname = (char *) malloc ( strlen (pathname) + 1 );
	oldname = (char *) malloc ( strlen (pathname) + 1 );
	strncpy(oldname, pathname, strlen (pathname) );
	strncpy(newname, pathname, strlen (pathname) );

	for ( i=0; i < npasses; i++ ) {
		rnd = (unsigned) random ();
		for ( j=0; j < len; j++ ) {
			newname[j+(basename-pathname)] = (char) ('A'+(rnd%26));
		}
		renameat ( dirfd, oldname, dirfd, newname );
		strncpy (oldname, newname, strlen (pathname) );
	}

	free (oldname);

	res = (*__lsr_real_unlinkat) (dirfd, newname, flags);
	free (newname);
	return res;
}

/* ======================================================= */

int
remove (const char * const pathname)
{

	__lsr_main ();
#ifdef LSR_DEBUG
	printf ("libsecrm: remove()\n");
	fflush (stdout);
#endif
	return unlink (pathname);
}

