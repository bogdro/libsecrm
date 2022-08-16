/*
 * A library for secure removing files.
 *	-- private file and program banning functions.
 *
 * Copyright (C) 2007-2015 Bogdan Drozdowski, bogdandr (at) op.pl
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
#ifndef HAVE_MALLOC
static char __lsr_linkpath[LSR_MAXPATHLEN];
static char __lsr_newlinkpath[LSR_MAXPATHLEN];
#endif
static const char * __lsr_valuable_files[] =
{
	/* The ".ICEauthority" part is a workaround an issue with
	   Kate and DCOP. */
	".ICEauthority",
	/* The sh-thd is a workaround an issue with BASH and
	   here-documents. */
	"sh-thd-",
	/* libsecrm's own files, like the banning file,
	   shouldn't be overwritten when libsecrm is using it */
	"libsecrm",
	/* rpmbuild temporary files */
	"rpm-tmp."
};

#if (defined HAVE_SYS_STAT_H) && (	\
	   (defined HAVE_DIRENT_H)	\
	|| (defined HAVE_NDIR_H)	\
	|| (defined HAVE_SYS_DIR_H)	\
	|| (defined HAVE_SYS_NDIR_H)	\
	)
# define LSR_CAN_USE_DIRS 1
#else
# undef LSR_CAN_USE_DIRS
#endif

#if (defined LSR_ENABLE_USERBANS) && (defined HAVE_GETENV) \
	&& (defined HAVE_STDLIB_H) && (defined HAVE_MALLOC)
# define LSR_CAN_USE_BANS 1
#else
# undef LSR_CAN_USE_BANS
#endif

#if (defined LSR_ENABLE_ENV) && (defined HAVE_STDLIB_H) && (defined HAVE_GETENV)
# define LSR_CAN_USE_ENV 1
#else
# undef LSR_CAN_USE_ENV
#endif

/******************* some of what's below comes from the 'fuser' utility ***************/

#ifdef LSR_CAN_USE_DIRS

# ifndef LSR_ANSIC
static int check_dir LSR_PARAMS((const pid_t pid, const char * const dirname, const char * const name));
# endif

static char __lsr_dirpath[LSR_MAXPATHLEN], __lsr_filepath[LSR_MAXPATHLEN];

/**
 * Browse the given /proc subdirectory to see if a file is listed there as being used.
 * @param pid the current process ID
 * @param dirname the name of the directory to browse
 * @param name the name of the file to look for
 */
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
#endif	/* LSR_CAN_USE_DIRS */

/* ======================================================= */

#if (defined LSR_CAN_USE_DIRS) && ((defined HAVE_SYS_TYPES_H)	\
	|| (defined MAJOR_IN_MKDEV) || (defined MAJOR_IN_SYSMACROS))

# ifndef LSR_ANSIC
static int check_map LSR_PARAMS((const pid_t pid, const char * const dirname, const char * const name));
# endif

# define LSR_BUFSIZ LSR_MAXPATHLEN
static char __lsr_pathname[LSR_MAXPATHLEN];
/*static char __lsr_dummy[LSR_MAXPATHLEN];*/
static char __lsr_line[LSR_BUFSIZ];

/**
 * Browse the given /proc memory map to see if a file is listed there as being used.
 * @param pid the current process ID
 * @param dirname the name of the directory to browse
 * @param name the name of the file to look for
 */
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
#endif /* (defined LSR_CAN_USE_DIRS) && ((defined HAVE_SYS_TYPES_H)	\
	|| (defined MAJOR_IN_MKDEV) || (defined MAJOR_IN_SYSMACROS)) */


/* ======================================================= */

/**
 * Check if the given file is opened by browsing /proc.
 * @param name the name of the file to look for
 */
int GCC_WARN_UNUSED_RESULT
__lsr_check_file_ban_proc (
#ifdef LSR_ANSIC
	const char * const name
# ifndef LSR_CAN_USE_DIRS
	LSR_ATTR ((unused))
# endif
	)
#else
	name)
	const char * const name
# ifndef LSR_CAN_USE_DIRS
		LSR_ATTR ((unused))
# endif
	;
#endif
{
	int res = 0;
#ifdef LSR_CAN_USE_DIRS
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
#endif	/* LSR_CAN_USE_DIRS */
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

/**
 * Gets the current executable name.
 * @param exename the place for the name
 * @param size the size of the exename array
 */
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
#ifdef LSR_CAN_USE_BANS
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
#ifdef LSR_CAN_USE_ENV
		if ( ret == 0 )
		{
			ret = __lsr_is_banned_in_file (__lsr_exename, getenv (LSR_PROG_BANNING_ENV));
		}
#endif
#ifdef LSR_CAN_USE_BANS
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
					full_path[(path_len + 1 + filesep_len + 1 + filename_len + 1)-1] = '\0';
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

# ifndef LSR_ANSIC
static int __lsr_is_forbidden_file LSR_PARAMS((const char * const name));
# endif

/**
 * Tells if the file with the given name is forbidden to be opened.
 * \param name The name of the file to check.
 * \return 1 if forbidden, 0 otherwise.
 */
static int __lsr_is_forbidden_file (
#ifdef LSR_ANSIC
	const char * const name)
#else
	name)
	const char * const name;
#endif
{
#ifdef HAVE_MALLOC
	char * __lsr_linkpath;
#endif
#if (defined HAVE_SYS_STAT_H) && (defined HAVE_READLINK)
	int res;
	off_t lsize;
	struct stat st;
# ifdef HAVE_MALLOC
	char * __lsr_newlinkpath;
# endif
#endif
#ifndef HAVE_MEMSET
	size_t i;
#endif
	unsigned int j;
	int ret = 0;

	if ( name == NULL )
	{
		return 0;
	}
	j = strlen (name) + 1;
#ifdef HAVE_MALLOC
	__lsr_linkpath = (char *) malloc ( j );
	if ( __lsr_linkpath != NULL )
#endif
	{
#ifndef HAVE_MALLOC
		j = sizeof (__lsr_linkpath);
#endif
#ifdef HAVE_MEMSET
		memset (__lsr_linkpath, 0, j);
#else
		for ( i = 0; i < j; i++ )
		{
			__lsr_linkpath[i] = '\0';
		}
#endif
		strncpy (__lsr_linkpath, name, j-1);
#if (defined HAVE_SYS_STAT_H) && (defined HAVE_READLINK) && (defined HAVE_LSTAT)
		res = lstat (name, &st);
		while ( res >= 0 )
		{
			if ( S_ISLNK (st.st_mode) )
			{
				lsize = st.st_size;
				if ( lsize <= 0 )
				{
					break;
				}
# ifdef HAVE_MALLOC
				__lsr_newlinkpath = (char *) malloc ((size_t)(lsize + 1));
				if ( __lsr_newlinkpath == NULL )
				{
					break;
				}
# else /* ! HAVE_MALLOC */
				lsize = sizeof (__lsr_newlinkpath)
# endif /* HAVE_MALLOC */
# ifdef HAVE_MEMSET
				memset (__lsr_newlinkpath, 0, (size_t)lsize);
# else
				for ( i = 0; i < lsize; i++ )
				{
					__lsr_newlinkpath[i] = '\0';
				}

# endif /* HAVE_MEMSET */
				res = readlink (__lsr_linkpath, __lsr_newlinkpath, (size_t)lsize);
				if ( (res < 0) || (res > lsize) )
				{
					break;
				}
				__lsr_newlinkpath[res] = '\0';
# ifdef HAVE_MALLOC
				if ( __lsr_linkpath != NULL )
				{
					free (__lsr_linkpath);
				}
				__lsr_linkpath = __lsr_newlinkpath;
# else
				strncpy (__lsr_linkpath, __lsr_newlinkpath, (size_t)res);
				__lsr_linkpath[res] = '\0';
# endif
			}
			else
			{
				break;
			}
			res = lstat (__lsr_linkpath, &st);
		}
#endif /* (defined HAVE_SYS_STAT_H) && (defined HAVE_READLINK) && (defined HAVE_LSTAT) */
		for ( j=0; j < sizeof (__lsr_valuable_files)/sizeof (__lsr_valuable_files[0]); j++)
		{
			if ( strstr (__lsr_linkpath, __lsr_valuable_files[j]) != NULL )
			{
				ret = 1;
				break;
			}
		}
	}
#ifdef HAVE_MALLOC
	if ( __lsr_linkpath != NULL )
	{
		free (__lsr_linkpath);
	}
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
	int ret = 0;	/* DEFAULT: NO, this file is not banned */
#ifdef LSR_CAN_USE_BANS
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

	/* check the known filenames that shouldn't be messed with: */
	if ( __lsr_is_forbidden_file (name) != 0 )
	{
		ret = 1;
	}

	if ( (ret == 0) && (__lsr_real_fopen_location () != NULL) )
	{
		ret = __lsr_is_banned_in_file (name, SYSCONFDIR LSR_PATH_SEP "libsecrm.fileban");
#ifdef LSR_CAN_USE_ENV
		if ( ret == 0 )
		{
			ret = __lsr_is_banned_in_file (name, getenv (LSR_FILE_BANNING_ENV));
		}
#endif
#ifdef LSR_CAN_USE_BANS
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
					full_path[(path_len + 1 + filesep_len + 1 + filename_len + 1)-1] = '\0';
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

