/*
 * A library for secure removing files.
 *	-- private file and program banning functions.
 *
 * Copyright (C) 2007-2013 Bogdan Drozdowski, bogdandr (at) op.pl
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

/* major, minor, makedev */
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
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

#ifdef MAJOR_IN_MKDEV
# include <sys/mkdev.h>
#else
# ifdef MAJOR_IN_SYSMACROS
#  include <sys/sysmacros.h>
# endif
#endif

#ifdef HAVE_STDLIB_H
# include <stdlib.h>	/* getenv() */
#endif

#ifdef HAVE_MALLOC_H
# include <malloc.h>
#endif

#include "libsecrm-priv.h"
#include "libsecrm.h"

#define  LSR_MAXPATHLEN 4097
static const char __lsr_progbanfilename[] = LSR_PROG_BANNING_USERFILE;
static const char __lsr_filebanfilename[] = LSR_FILE_BANNING_USERFILE;
static char __lsr_exename[LSR_MAXPATHLEN];
static char __lsr_omitfile[LSR_MAXPATHLEN];

/******************* some of what's below comes from the 'fuser' utility ***************/

#if (defined HAVE_SYS_STAT_H) && (	\
	   (defined HAVE_DIRENT_H)	\
	|| (defined HAVE_NDIR_H)	\
	|| (defined HAVE_SYS_DIR_H)	\
	|| (defined HAVE_SYS_NDIR_H)	\
	)

# ifndef LSR_ANSIC
static int check_dir LSR_PARAMS((const pid_t pid, const char * const dirname, const char * const name));
# endif

static char __lsr_dirpath[LSR_MAXPATHLEN], __lsr_filepath[LSR_MAXPATHLEN];

static int
check_dir (
# ifdef LSR_ANSIC
	const pid_t pid, const char * const dirname, const char * const name)
# else
	pid, dirname, name)
	const pid_t pid;
	const char * const dirname;
	const char * const name;
# endif
{
	int res = 0;
	DIR * dirp;
	const struct dirent * direntry;
	struct stat st_orig, st_dyn;

# ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: check_map(%d, %s, %s)\n", pid,
		(dirname != NULL)? dirname : "null", (name != NULL)? name : "null");
	fflush (stderr);
# endif

	if ( (dirname == NULL) || (name == NULL) )
	{
		/* Can't check - assume not banned for now. This directory may simply not exist. */
		return 0;
	}

	if ( stat (name, &st_orig) < 0 )
	{
		/* Can't stat - always banned */
		return 1;
	}

	/* create the path "/proc/pid/dirname", like "/proc/3999/fd" */
# ifdef HAVE_SNPRINTF
	snprintf (__lsr_dirpath, LSR_MAXPATHLEN-1, "/proc/%d/%s", pid, dirname);
# else
	sprintf (__lsr_dirpath, "/proc/%*d/%*s", 9, pid, LSR_MAXPATHLEN-17-1, dirname);
# endif
	__lsr_dirpath[LSR_MAXPATHLEN-1] = '\0';
	dirp = opendir (__lsr_dirpath);
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
		snprintf (__lsr_filepath, LSR_MAXPATHLEN-1, "/proc/%d/%s/%s",
			pid, dirname, direntry->d_name);
# else
		sprintf (__lsr_filepath, "/proc/%*d/%*s/%*s",
			9, pid, LSR_MAXPATHLEN/2, dirname, LSR_MAXPATHLEN/2, direntry->d_name);
# endif
		__lsr_filepath[LSR_MAXPATHLEN-1] = '\0';
		if (stat (__lsr_filepath, &st_dyn) != 0)	/* NOT lstat() ! */
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

# ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: check_map(%d, %s, %s)=%d\n", pid,
		(dirname != NULL)? dirname : "null", (name != NULL)? name : "null", res);
	fflush (stderr);
# endif

	closedir (dirp);
	return res;
}
#endif	/* (defined HAVE_DIRENT_H) && (defined HAVE_SYS_STAT_H) */

/* ======================================================= */

#if (defined HAVE_SYS_STAT_H) && (	\
	   (defined HAVE_DIRENT_H)	\
	|| (defined HAVE_NDIR_H)	\
	|| (defined HAVE_SYS_DIR_H)	\
	|| (defined HAVE_SYS_NDIR_H)	\
	) && ((defined HAVE_SYS_TYPES_H)	\
	|| (defined MAJOR_IN_MKDEV) || (defined MAJOR_IN_SYSMACROS))

# ifndef LSR_ANSIC
static int check_map LSR_PARAMS((const pid_t pid, const char * const dirname, const char * const name));
# endif

# define LSR_BUFSIZ LSR_MAXPATHLEN
static char __lsr_pathname[LSR_MAXPATHLEN];
/*static char __lsr_dummy[LSR_MAXPATHLEN];*/
static char __lsr_line[LSR_BUFSIZ];

static int
check_map (
# ifdef LSR_ANSIC
	const pid_t pid, const char * const dirname, const char * const name)
# else
	pid, dirname, name)
	const pid_t pid;
	const char * const dirname;
	const char * const name;
# endif
{
	int res = 0;
	FILE *fp;
	union u
	{
# ifdef HAVE_LONG_LONG
		unsigned long long int ll;
# else
		unsigned long int ll;
# endif
		ino_t tmp_inode;
	} tmp_inode;
	struct stat st_orig;
	unsigned int tmp_maj, tmp_min;

# ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: check_map(%d, %s, %s)\n", pid,
		(dirname != NULL)? dirname : "null", (name != NULL)? name : "null");
	fflush (stderr);
# endif

	if ( (dirname == NULL) || (name == NULL) )
	{
		/* Can't check - assume not banned for now. This directory may simply not exist. */
		return 0;
	}

	if ( __lsr_real_fopen_location () == NULL )
	{
		return 0;
	}

	if ( stat (name, &st_orig) < 0 )
	{
		/* Can't stat - always banned */
		return 1;
	}


	if ( __lsr_real_fopen_location () != NULL )
	{
		/* create the path "/proc/pid/dirname", like "/proc/3999/fd" */
# ifdef HAVE_SNPRINTF
		snprintf (__lsr_pathname, LSR_MAXPATHLEN - 1, "/proc/%d/%s", pid, dirname);
# else
		sprintf (__lsr_pathname, "/proc/%*d/%*s", 9, pid, LSR_MAXPATHLEN-10, dirname);
# endif
		__lsr_pathname[LSR_MAXPATHLEN-1] = '\0';
		fp = (*__lsr_real_fopen_location ()) (__lsr_pathname, "r");
		if ( fp == NULL )
		{
			return 0;
		}
		while ( fgets (__lsr_line, LSR_BUFSIZ, fp) != NULL )
		{
			__lsr_line[LSR_BUFSIZ-1] = '\0';
# ifdef HAVE_LONG_LONG
			tmp_inode.ll = 0LL;
			/*if ( sscanf (__lsr_line, "%s %s %s %x:%x %llu", __lsr_dummy, __lsr_dummy, __lsr_dummy,
						&tmp_maj, &tmp_min, &tmp_inode.ll) == 6 )*/
			if ( sscanf (__lsr_line, "%*s %*s %*s %x:%x %llu",
						&tmp_maj, &tmp_min, &tmp_inode.ll) == 6 )
# else
			/*if ( sscanf (__lsr_line, "%s %s %s %x:%x %lu", __lsr_dummy, __lsr_dummy, __lsr_dummy,
						&tmp_maj, &tmp_min, &tmp_inode.ll) == 6 )*/
			if ( sscanf (__lsr_line, "%*s %*s %*s %x:%x %lu",
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
	}
# ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: check_map(%d, %s, %s)=%d\n", pid,
		(dirname != NULL)? dirname : "null", (name != NULL)? name : "null", res);
	fflush (stderr);
# endif

	return res;
}
#endif /* (defined HAVE_SYS_STAT_H) */


/* ======================================================= */

int GCC_WARN_UNUSED_RESULT
__lsr_check_file_ban_proc (
#ifdef LSR_ANSIC
	const char * const name
# if ! ((defined HAVE_SYS_STAT_H) && (	\
	   (defined HAVE_DIRENT_H)	\
	|| (defined HAVE_NDIR_H)	\
	|| (defined HAVE_SYS_DIR_H)	\
	|| (defined HAVE_SYS_NDIR_H)	\
	))
	LSR_ATTR ((unused))
# endif
	)
#else
	name)
	const char * const name
# if ! ((defined HAVE_SYS_STAT_H) && (	\
	   (defined HAVE_DIRENT_H)	\
	|| (defined HAVE_NDIR_H)	\
	|| (defined HAVE_SYS_DIR_H)	\
	|| (defined HAVE_SYS_NDIR_H)	\
	))
		LSR_ATTR ((unused))
# endif
	;
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
	pid_t my_pid;

	if ( name == NULL )
	{
		/* Can't check - assume not banned for now. This directory may simply not exist. */
		return 0;
	}

	my_pid = getpid ();
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
		if ( topproc_dent->d_name == NULL )
		{
			continue;
		}
		if ( (topproc_dent->d_name[0] < '0') || (topproc_dent->d_name[0] > '9') )
		{
			/* Not a process ID */
			continue;
		}
		if ( sscanf (topproc_dent->d_name, "%d", &pid) < 1 )
		{
			continue;
		}
		if ( pid == my_pid )
		{
			/* the process which is manipulating the file can have it open */
			continue;
		}
		res += check_dir (pid, "lib" , name);
		if ( res != 0 )
		{
			break;
		}
		res += check_dir (pid, "mmap", name);
		if ( res != 0 )
		{
			break;
		}
		res += check_dir (pid, "fd"  , name);
		if ( res != 0 )
		{
			break;
		}
# if ((defined HAVE_SYS_TYPES_H)	\
	|| (defined MAJOR_IN_MKDEV) || (defined MAJOR_IN_SYSMACROS))
		res += check_map (pid, "maps", name);
		if ( res != 0 )
		{
			break;
		}
# endif
	}

	closedir (topproc_dir);
	__lsr_set_internal_function (0);
#endif	/* (defined HAVE_DIRENT_H) && (defined HAVE_SYS_STAT_H) */
#ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: __lsr_check_file_ban_proc(%s)=%d\n", (name != NULL)? name : "null", res);
	fflush (stderr);
#endif

	return res;
}


/******************* some of what's below comes from libsafe ***************/

#ifndef LSR_ANSIC
static char * __lsr_get_exename LSR_PARAMS((char * const exename, const size_t size));
#endif
static char *
__lsr_get_exename (
#ifdef LSR_ANSIC
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
	if ( exename == NULL )
	{
		/* Can't check - assume not banned for now. This directory may simply not exist. */
		return 0;
	}

	for ( i = 0; i < size; i++ )
	{
		exename[i] = '\0';
	}
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

/* =============================================================== */

#ifndef LSR_ANSIC
static int
__lsr_is_banned_in_file LSR_PARAMS((const char * const exename, const char * const ban_file_name));
#endif

/**
 * Checks if the given program is banned (listed) in the given file.
 * \param exename The program name to check.
 * \param ban_file_name The name of the banning file to check.
 * \return The buffer.
 */
static int GCC_WARN_UNUSED_RESULT
__lsr_is_banned_in_file (
#ifdef LSR_ANSIC
	const char * const exename, const char * const ban_file_name)
#else
	exename, ban_file_name)
	const char * const exename;
	const char * const ban_file_name;
#endif
{
	FILE *fp;
	int ret = 0;	/* DEFAULT: NO, this program is not banned */
	size_t line_len;
#ifdef HAVE_ERRNO_H
	int err = 0;
#endif

	if ( (exename == NULL) || (ban_file_name == NULL) )
	{
		return ret;
	}

#ifdef HAVE_ERRNO_H
	err = errno;
#endif
	fp = (*__lsr_real_fopen_location ()) (ban_file_name, "r");
	if ( fp != NULL )
	{
		while ( fgets (__lsr_omitfile, sizeof (__lsr_omitfile), fp) != NULL )
		{
			__lsr_omitfile[LSR_MAXPATHLEN - 1] = '\0';

			if ( (__lsr_omitfile[0] != '\0') /*(strlen (__lsr_omitfile) > 0)*/
				&& (__lsr_omitfile[0] != '\n')
				&& (__lsr_omitfile[0] != '\r') )
			{
				do
				{
					line_len = strlen (__lsr_omitfile);
					if ( line_len == 0 )
					{
						break;
					}
					if ( (__lsr_omitfile[line_len-1] == '\r')
						|| (__lsr_omitfile[line_len-1] == '\n') )
					{
						__lsr_omitfile[line_len-1] = '\0';
					}
					else
					{
						break;
					}
				}
				while ( line_len != 0 );
				if ( line_len == 0 )
				{
					/* empty line in file - shouldn't happen here */
					continue;
				}
				/*if (strncmp (omitfile, exename, sizeof (omitfile)) == 0)*/
				/* NOTE the reverse parameters */
				/* char *strstr(const char *haystack, const char *needle); */
				if (strstr (exename, __lsr_omitfile) != NULL)
				{
					/* needle found in haystack */
					ret = 1;	/* YES, this program is banned */
					break;
				}
			}
		}
		fclose (fp);
	}
#ifdef HAVE_ERRNO_H
	errno = err;
#endif
	return ret;
}


/* ======================================================= */

/**
 * Checks if the current program is banned from LibSecRm (shouldn't be messed with).
 * @return non-zero if the current program is banned from LibSecRm.
 */
int GCC_WARN_UNUSED_RESULT
__lsr_check_prog_ban (
#ifdef LSR_ANSIC
	void
#endif
)
{
	int	ret = 0;	/* DEFAULT: NO, this program is not banned */
#if (defined LSR_ENABLE_USERBANS) && (defined HAVE_GETENV) \
	&& (defined HAVE_STDLIB_H) && (defined HAVE_MALLOC)
	char *path = NULL;
	char * full_path = NULL;
	size_t path_len;
	static size_t filename_len = 0;
	static size_t filesep_len = 0;
#endif

	/* marker for malloc: */
	__lsr_set_internal_function (1);
	/* Is this process on the list of applications to ignore? */
	__lsr_get_exename (__lsr_exename, LSR_MAXPATHLEN);
	__lsr_exename[LSR_MAXPATHLEN-1] = '\0';
#ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: __lsr_check_prog_ban(): exename='%s'\n", __lsr_exename);
	fflush (stderr);
#endif

	if ( __lsr_exename[0] == '\0' /*strlen (__lsr_exename) == 0*/ )
	{
		/* can't find executable name. Assume not banned */
		__lsr_set_internal_function (0);
		return 0;
	}

	if ( __lsr_real_fopen_location () != NULL )
	{
		ret = __lsr_is_banned_in_file (__lsr_exename, SYSCONFDIR LSR_PATH_SEP "libsecrm.progban");
#if (defined LSR_ENABLE_ENV) && (defined HAVE_STDLIB_H) && (defined HAVE_GETENV)
		if ( ret == 0 )
		{
			ret = __lsr_is_banned_in_file (__lsr_exename, getenv (LSR_PROG_BANNING_ENV));
		}
#endif
#if (defined LSR_ENABLE_USERBANS) && (defined HAVE_GETENV) \
	&& (defined HAVE_STDLIB_H) && (defined HAVE_MALLOC)
		if ( ret == 0 )
		{
			path = getenv ("HOME");
			if ( path != NULL )
			{
				path_len = strlen (path);
				if ( filename_len == 0 )
				{
					filename_len = strlen (__lsr_progbanfilename);
				}
				if ( filesep_len == 0 )
				{
					filesep_len = strlen (LSR_PATH_SEP);
				}
				full_path = (char *) malloc (path_len + 1 + filesep_len + 1 + filename_len + 1);
				if ( full_path != NULL )
				{
					strncpy (full_path, path, path_len+1);
					strncat (full_path, LSR_PATH_SEP, filesep_len+1);
					strncat (full_path, __lsr_progbanfilename, filename_len+1);
					ret = __lsr_is_banned_in_file (__lsr_exename, full_path);
					free (full_path);
				}
			}
		}
#endif
	}
	__lsr_set_internal_function (0);
#ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: __lsr_check_prog_ban()=%d\n", ret);
	fflush (stderr);
#endif

	return ret;
}

/* ======================================================= */

/**
 * Checks if the given file is banned from LibSecRm (shouldn't be messed with).
 * @return non-zero if the given file is banned from LibSecRm.
 */
int GCC_WARN_UNUSED_RESULT
__lsr_check_file_ban (
#ifdef LSR_ANSIC
	const char * const name)
#else
	name)
	const char * const name;
#endif
{
	int	ret = 0;	/* DEFAULT: NO, this file is not banned */
#if (defined LSR_ENABLE_USERBANS) && (defined HAVE_GETENV) \
	&& (defined HAVE_STDLIB_H) && (defined HAVE_MALLOC)
	char *path = NULL;
	char * full_path = NULL;
	size_t path_len;
	static size_t filename_len = 0;
	static size_t filesep_len = 0;
#endif

#ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: __lsr_check_file_ban(%s)\n", (name != NULL)? name : "null");
	fflush (stderr);
#endif
	/* no filename means banned */
	if ( name == NULL )
	{
		return 1;
	}
	if ( name[0] == '\0' /*strlen (name) == 0*/ )
	{
		return 1;
	}

	/* marker for malloc: */
	__lsr_set_internal_function (1);
	if ( __lsr_real_fopen_location () != NULL )
	{
		ret = __lsr_is_banned_in_file (name, SYSCONFDIR LSR_PATH_SEP "libsecrm.fileban");
#if (defined LSR_ENABLE_ENV) && (defined HAVE_STDLIB_H) && (defined HAVE_GETENV)
		if ( ret == 0 )
		{
			ret = __lsr_is_banned_in_file (name, getenv (LSR_FILE_BANNING_ENV));
		}
#endif
#if (defined LSR_ENABLE_USERBANS) && (defined HAVE_GETENV) \
	&& (defined HAVE_STDLIB_H) && (defined HAVE_MALLOC)
		if ( ret == 0 )
		{
			path = getenv ("HOME");
			if ( path != NULL )
			{
				path_len = strlen (path);
				if ( filename_len == 0 )
				{
					filename_len = strlen (__lsr_filebanfilename);
				}
				if ( filesep_len == 0 )
				{
					filesep_len = strlen (LSR_PATH_SEP);
				}
				full_path = (char *) malloc (path_len + 1 + filesep_len + 1 + filename_len + 1);
				if ( full_path != NULL )
				{
					strncpy (full_path, path, path_len+1);
					strncat (full_path, LSR_PATH_SEP, filesep_len+1);
					strncat (full_path, __lsr_filebanfilename, filename_len+1);
					ret = __lsr_is_banned_in_file (name, full_path);
					free (full_path);
				}
			}
		}
#endif
	}
	__lsr_set_internal_function (0);
#ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: __lsr_check_file_ban(%s)=%d\n", (name != NULL)? name : "null", ret);
	fflush (stderr);
#endif
	return ret;
}

