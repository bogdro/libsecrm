/*
 * A library for secure removing files.
 *	-- private file and program banning functions.
 *
 * Copyright (C) 2007-2009 Bogdan Drozdowski, bogdandr (at) op.pl
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
#include "lsr_paths.h"

#ifdef HAVE_SYS_STAT_H
# ifdef STAT_MACROS_BROKEN
#  if STAT_MACROS_BROKEN
#   error Stat macros broken. Change your C library.
#  endif
# endif
#endif

#define _LARGEFILE64_SOURCE 1

#include <stdio.h>

#ifdef HAVE_STRING_H
# if (!defined STDC_HEADERS) && (defined HAVE_MEMORY_H)
#  include <memory.h>
# endif
# include <string.h>
#endif

#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#ifdef HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) strlen((dirent)->d_name)
#else
# define dirent direct
# define NAMLEN(dirent) (dirent)->d_namlen
# ifdef HAVE_SYS_NDIR_H
#  include <sys/ndir.h>
# endif
# ifdef HAVE_SYS_DIR_H
#  include <sys/dir.h>
# endif
# ifdef HAVE_NDIR_H
#  include <ndir.h>
# endif
#endif

#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif

/* major, minor, makedev */
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef MAJOR_IN_MKDEV
# include <sys/mkdev.h>
#else
# ifdef MAJOR_IN_SYSMACROS
#  include <sys/sysmacros.h>
# endif
#endif

#include "libsecrm-priv.h"

#define  LSR_MAXPATHLEN 4097

/******************* some of what's below comes from the 'fuser' utility ***************/

#if (defined HAVE_SYS_STAT_H) && (	\
	   (defined HAVE_DIRENT_H)	\
	|| (defined HAVE_NDIR_H)	\
	|| (defined HAVE_SYS_DIR_H)	\
	|| (defined HAVE_SYS_NDIR_H)	\
	)

static int
check_dir (
# if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	const pid_t pid, const char * const dirname, const char * const name)
# else
	pid, dirname, name)
	const pid_t pid;
	const char * const dirname;
	const char * const name;
# endif
{
	int res = 0;
	char dirpath[LSR_MAXPATHLEN], filepath[LSR_MAXPATHLEN];
	DIR * dirp;
	const struct dirent * direntry;
	struct stat st_orig, st_dyn;

	if ( stat (name, &st_orig) < 0 )
	{
		/* Can't stat - always banned */
		return 1;
	}

	/* create the path "/proc/pid/dirname", like "/proc/3999/fd" */
# ifdef HAVE_SNPRINTF
	snprintf (dirpath, LSR_MAXPATHLEN, "/proc/%d/%s", pid, dirname);
# else
	sprintf (dirpath, "/proc/%*d/%*s", 9, pid, LSR_MAXPATHLEN-10, dirname);
# endif
	dirp = opendir (dirpath);
	if ( dirp == NULL )
	{
		/* Can't check - assume not banned for now. This directory may simply not exist. */
		return 0;
	}
	while ( (direntry = readdir (dirp)) != NULL)
	{
		/*
		if (direntry->d_name[0] < '0' || direntry->d_name[0] > '9')
		{
			continue;
		}
		*/

		/* create the path "/proc/pid/dirname/element", like "/proc/3999/fd/1" */
# ifdef HAVE_SNPRINTF
		snprintf (filepath, LSR_MAXPATHLEN, "/proc/%d/%s/%s",
			pid, dirname, direntry->d_name);
# else
		sprintf (filepath, "/proc/%*d/%*s/%*s",
			9, pid, LSR_MAXPATHLEN/2, dirname, LSR_MAXPATHLEN/2, direntry->d_name);
# endif
		if (stat (filepath, &st_dyn) != 0)	/* NOT lstat() ! */
		{
			/* Just skip it. We may get results like "67 -> socket:[13006]",
			   so stat() would fail */
			continue;
		}
		else
		{
			if ( (st_dyn.st_dev == st_orig.st_dev) && (st_dyn.st_ino == st_orig.st_ino) )
			{
				res = 1;
				break;
			}
		}
		if ( res != 0 )
		{
			break;
		}
	} /* while direntry */

	closedir (dirp);
	return res;
}
#endif	/* (defined HAVE_DIRENT_H) && (defined HAVE_SYS_STAT_H) */

#if (defined HAVE_SYS_STAT_H) && ((defined HAVE_SYS_TYPES_H)	\
	|| (defined MAJOR_IN_MKDEV) || (defined MAJOR_IN_SYSMACROS))

static int
check_map (
# if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	const pid_t pid, const char * const dirname, const char * const name)
# else
	pid, dirname, name)
	const pid_t pid;
	const char * const dirname;
	const char * const name;
# endif
{
	int res = 0;
	char pathname[LSR_MAXPATHLEN];
	char dummy[LSR_MAXPATHLEN];
# define LSR_BUFSIZ LSR_MAXPATHLEN
	char line[LSR_BUFSIZ];
	FILE *fp;
	union u
	{
# ifdef HAVE_LONG_LONG
		unsigned long long ll;
# else
		unsigned long ll;
# endif
		ino_t tmp_inode;
	} tmp_inode;
	struct stat st_orig;
	unsigned int tmp_maj, tmp_min;

	if ( __lsr_real_fopen_location () == NULL )
	{
		return 0;
	}

	if ( stat (name, &st_orig) < 0 )
	{
		/* Can't stat - always banned */
		return 1;
	}


	/* create the path "/proc/pid/dirname", like "/proc/3999/fd" */
# ifdef HAVE_SNPRINTF
	snprintf (pathname, LSR_MAXPATHLEN, "/proc/%d/%s", pid, dirname);
# else
	sprintf (pathname, "/proc/%*d/%*s", 9, pid, LSR_MAXPATHLEN-10, dirname);
# endif
	fp = (*__lsr_real_fopen_location ()) (pathname, "r");
	if ( fp == NULL )
	{
		return 0;
	}
	while ( fgets (line, LSR_BUFSIZ, fp) != NULL )
	{
# ifdef HAVE_LONG_LONG
		tmp_inode.ll = 0LL;
		if ( sscanf (line, "%s %s %s %x:%x %llu", dummy, dummy, dummy,
					&tmp_maj, &tmp_min, &tmp_inode.ll) == 6 )
# else
		if ( sscanf (line, "%s %s %s %x:%x %lu", dummy, dummy, dummy,
					&tmp_maj, &tmp_min, &tmp_inode.ll) == 6 )
# endif
		{
			if ( (st_orig.st_dev == makedev (tmp_maj, tmp_min))
				&& (st_orig.st_ino == tmp_inode.tmp_inode)
				)
			{
				res = 1;
				break;
			}
		}
	}
	fclose (fp);
	return res;
}
#endif /* (defined HAVE_SYS_STAT_H) */


int GCC_WARN_UNUSED_RESULT
__lsr_check_file_ban_proc (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	const char * const name
# if (!defined HAVE_DIRENT_H) && (!defined HAVE_NDIR_H)	\
	&& (!defined HAVE_SYS_DIR_H) && (!defined HAVE_SYS_NDIR_H)
	LSR_ATTR ((unused))
# endif
	)
#else
	name)
	const char * const name;
#endif
{
	int res = 0;
#if (defined HAVE_SYS_STAT_H) && (	\
	   (defined HAVE_DIRENT_H)	\
	|| (defined HAVE_NDIR_H)	\
	|| (defined HAVE_SYS_DIR_H)	\
	|| (defined HAVE_SYS_NDIR_H)	\
	)
	DIR * topproc_dir;
	struct dirent * topproc_dent;
	pid_t pid;

	/* marker for malloc: */
	__lsr_set_internal_function (1);
	topproc_dir = opendir ("/proc");
	if ( topproc_dir == NULL)
	{
		/* Can't check - assume not banned for now. */
		return 0;
	}
	while ( (topproc_dent = readdir (topproc_dir)) != NULL )
	{
		if ( (topproc_dent->d_name[0] < '0') || (topproc_dent->d_name[0] > '9') )
		{
			/* Not a process */
			continue;
		}
		if ( sscanf (topproc_dent->d_name, "%d", &pid) < 1 )
		{
			continue;
		}
		res += check_dir (pid, "lib" , name);
		if ( res != 0 ) break;
		res += check_dir (pid, "mmap", name);
		if ( res != 0 ) break;
		res += check_dir (pid, "fd"  , name);
		if ( res != 0 ) break;

		res += check_map (pid, "maps", name);
		if ( res != 0 ) break;
	}

	closedir (topproc_dir);
	__lsr_set_internal_function (0);
#endif	/* (defined HAVE_DIRENT_H) && (defined HAVE_SYS_STAT_H) */
	return res;
}


/******************* some of what's below comes from libsafe ***************/

static char *
__lsr_get_exename (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	char * const exename, const size_t size)
#else
	exename, size)
	char * const exename;
	const size_t size;
#endif
{
	size_t i;
#ifdef HAVE_READLINK
	ssize_t res;
#endif
#ifdef HAVE_ERRNO_H
	int err = 0;
#endif
	for ( i=0; i < size; i++ ) exename[i] = '\0';
	/* get the name of the current executable */
#ifdef HAVE_ERRNO_H
	err = errno;
#endif
#ifdef HAVE_READLINK
	res = readlink ("/proc/self/exe", exename, size - 1);
	if (res == -1)
	{
		exename[0] = '\0';
	}
	else
	{
		exename[res] = '\0';
	}
#else
	exename[0] = '\0';
#endif
#ifdef HAVE_ERRNO_H
	errno = err;
#endif
	return exename;
}

int GCC_WARN_UNUSED_RESULT
__lsr_check_prog_ban (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	void
#endif
)
{
	char    exename[LSR_MAXPATHLEN];	/* 4096 */
	char    omitfile[LSR_MAXPATHLEN];
	FILE    *fp;
	int	ret = 0;	/* DEFAULT: NO, this program is not banned */

	/* marker for malloc: */
	__lsr_set_internal_function (1);
	/* Is this process on the list of applications to ignore? */
	__lsr_get_exename (exename, LSR_MAXPATHLEN);
	exename[LSR_MAXPATHLEN-1] = '\0';
	if ( strlen (exename) == 0 )
	{
		/* can't find executable name. Assume not banned */
		__lsr_set_internal_function (0);
		return 0;
	}

	if ( __lsr_real_fopen_location () != NULL )
	{
		fp = (*__lsr_real_fopen_location ()) (SYSCONFDIR LSR_PATH_SEP "libsecrm.progban", "r");
		if (fp != NULL)
		{
			while ( fgets (omitfile, sizeof (omitfile), fp) != NULL )
			{
				omitfile[LSR_MAXPATHLEN - 1] = '\0';

				if ( (strlen (omitfile) > 0) && (omitfile[0] != '\n')
					&& (omitfile[0] != '\r') )
				{
					/*if (strncmp (omitfile, exename, sizeof (omitfile)) == 0)*/
					/* NOTE the reverse parameters */
					/* char *strstr(const char *haystack, const char *needle); */
					if (strstr (exename, omitfile) != NULL)
					{
						/* needle found in haystack */
						fclose (fp);
						ret = 1;	/* YES, this program is banned */
					}
				}
			}
			fclose (fp);
		}
	}
	__lsr_set_internal_function (0);
	return ret;
}

int GCC_WARN_UNUSED_RESULT
__lsr_check_file_ban (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	const char * const name)
#else
	name)
	const char * const name;
#endif
{
	char    omitfile[LSR_MAXPATHLEN];
	FILE    *fp;
	int	ret = 0;	/* DEFAULT: NO, this file is not banned */

	/* no filename means banned */
	if ( name == NULL )
	{
		return 1;
	}
	if ( strlen (name) == 0 )
	{
		return 1;
	}

	/* marker for malloc: */
	__lsr_set_internal_function (1);
        fp = (*__lsr_real_fopen_location ()) (SYSCONFDIR LSR_PATH_SEP "libsecrm.fileban", "r");
	if (fp != NULL)
	{
		while ( fgets (omitfile, sizeof (omitfile), fp) != NULL )
		{
			omitfile[LSR_MAXPATHLEN - 1] = '\0';

			if ( (strlen (omitfile) > 0) && (omitfile[0] != '\n') && (omitfile[0] != '\r') )
			{
				/* NOTE the reverse parameters */
				/* char *strstr(const char *haystack, const char *needle); */
				if (strstr (name, omitfile) != NULL) /* needle found in haystack */
				{
					fclose (fp);
					ret = 1;	/* YES, this file is banned */
				}
			}
		}
		fclose (fp);
	}
	__lsr_set_internal_function (0);
	return ret;
}

