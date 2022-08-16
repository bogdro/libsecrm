/*
 * A library for secure removing files.
 *	-- private file and program banning functions.
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
#include "lsr_paths.h"

#define _LARGEFILE64_SOURCE 1
#define _ATFILE_SOURCE 1

/* major, minor, makedev */
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

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

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
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

#include "lsr_priv.h"
#include "libsecrm.h"

#define  LSR_MAXPATHLEN 4097
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
# define BANNING_CAN_USE_BANS 1
#else
# undef LSR_CAN_USE_BANS
# define BANNING_CAN_USE_BANS 0
#endif

#if (defined LSR_ENABLE_ENV) && (defined HAVE_STDLIB_H) && (defined HAVE_GETENV)
# define LSR_CAN_USE_ENV 1
# define BANNING_ENABLE_ENV 1
#else
# undef LSR_CAN_USE_ENV
# define BANNING_ENABLE_ENV 0
#endif

#ifdef LSR_ANSIC
# define BANNING_ANSIC 1
#else
# define BANNING_ANSIC 0
#endif

#define BANNING_SET_ERRNO(value) LSR_SET_ERRNO(value)
#define BANNING_GET_ERRNO(value) LSR_GET_ERRNO(variable)
#define BANNING_MAKE_ERRNO_VAR(x) LSR_MAKE_ERRNO_VAR(x)
#define BANNING_MAXPATHLEN LSR_MAXPATHLEN
#define BANNING_PATH_SEP LSR_PATH_SEP
#define BANNING_MKNAME(x) __lsr ## x
#define BANNING_PARAMS(x) LSR_PARAMS(x)

#ifndef HAVE_READLINK
# define HAVE_READLINK 0
#endif
#ifndef HAVE_GETENV
# define HAVE_GETENV 0
#endif

#include <banning-generic.c>

#if HAVE_READLINK == 0
# undef HAVE_READLINK
#endif
#if HAVE_GETENV == 0
# undef HAVE_GETENV
#endif

/******************* some of what's below comes from the 'fuser' utility ***************/

#ifdef LSR_CAN_USE_DIRS

# ifndef LSR_ANSIC
static int check_dir LSR_PARAMS((const pid_t pid,
	const char * const dirname, const char * const name));
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
	fprintf (stderr, "libsecrm: check_dir(%d, %s, %s)\n", pid,
		(dirname != NULL)? dirname : "null",
		(name != NULL)? name : "null");
	fflush (stderr);
# endif

	if ( (dirname == NULL) || (name == NULL) )
	{
		/* Can't check - assume not banned for now. This directory
			may simply not exist. */
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
	sprintf (__lsr_dirpath, "/proc/%*d/%*s", 9, pid,
		LSR_MAXPATHLEN-17-1, dirname);
# endif
	__lsr_dirpath[LSR_MAXPATHLEN-1] = '\0';
	dirp = opendir (__lsr_dirpath);
	if ( dirp == NULL )
	{
		/* Can't check - assume not banned for now. This directory
			may simply not exist. */
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
			9, pid, LSR_MAXPATHLEN/2, dirname,
			LSR_MAXPATHLEN/2, direntry->d_name);
# endif
		__lsr_filepath[LSR_MAXPATHLEN-1] = '\0';
		if (stat (__lsr_filepath, &st_dyn) != 0)	/* NOT lstat() ! */
		{
			/* Just skip it. We may get results like
			"67 -> socket:[13006]", so stat() would fail */
			continue;
		}
		else
		{
			if ( (st_dyn.st_dev == st_orig.st_dev)
				&& (st_dyn.st_ino == st_orig.st_ino) )
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
		(dirname != NULL)? dirname : "null",
		(name != NULL)? name : "null", res);
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
static int check_map LSR_PARAMS((const pid_t pid,
	const char * const dirname, const char * const name));
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
		(dirname != NULL)? dirname : "null",
		(name != NULL)? name : "null");
	fflush (stderr);
# endif

	if ( (dirname == NULL) || (name == NULL) )
	{
		/* Can't check - assume not banned for now. This directory
			may simply not exist. */
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
		snprintf (__lsr_pathname, LSR_MAXPATHLEN - 1,
			"/proc/%d/%s", pid, dirname);
# else
		sprintf (__lsr_pathname, "/proc/%*d/%*s", 9, pid,
			LSR_MAXPATHLEN-10, dirname);
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
			/*if ( sscanf (__lsr_line, "%s %s %s %x:%x %llu",
				__lsr_dummy, __lsr_dummy, __lsr_dummy,
				&tmp_maj, &tmp_min, &tmp_inode.ll) == 6 )*/
			if ( sscanf (__lsr_line, "%*s %*s %*s %x:%x %llu",
					&tmp_maj, &tmp_min, &tmp_inode.ll) == 3 )
# else
			/*if ( sscanf (__lsr_line, "%s %s %s %x:%x %lu",
				__lsr_dummy, __lsr_dummy, __lsr_dummy,
				&tmp_maj, &tmp_min, &tmp_inode.ll) == 6 )*/
			if ( sscanf (__lsr_line, "%*s %*s %*s %x:%x %lu",
					&tmp_maj, &tmp_min, &tmp_inode.ll) == 3 )
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
		(dirname != NULL)? dirname : "null",
		(name != NULL)? name : "null", res);
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
	LSR_MAKE_ERRNO_VAR(err);
	int res = 0;
#ifdef LSR_CAN_USE_DIRS
	DIR * topproc_dir;
	struct dirent * topproc_dent;
	pid_t pid;
	pid_t my_pid;

	if ( name == NULL )
	{
		/* Can't check - assume not banned for now. This directory
			may simply not exist. */
		return 0;
	}

	my_pid = getpid ();
	/* marker for malloc: */
	__lsr_set_internal_function (1);
	topproc_dir = opendir ("/proc");
	if ( topproc_dir == NULL)
	{
		/* Can't check - assume not banned for now. */
		LSR_SET_ERRNO (err);
		return 0;
	}
	while ( (topproc_dent = readdir (topproc_dir)) != NULL )
	{
		if ( topproc_dent->d_name == NULL )
		{
			continue;
		}
		if ( (topproc_dent->d_name[0] < '0')
			|| (topproc_dent->d_name[0] > '9') )
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
			/* the process which is manipulating the
			file can have it open */
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
	fprintf (stderr, "libsecrm: __lsr_check_file_ban_proc(%s)=%d\n",
		(name != NULL)? name : "null", res);
	fflush (stderr);
#endif
	LSR_SET_ERRNO (err);

	return res;
}


/******************* some of what's below comes from libsafe ***************/

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
	LSR_MAKE_ERRNO_VAR(err);

	/* marker for malloc: */
	__lsr_set_internal_function (1);
	/* Is this process on the list of applications to ignore? */
	__banning_get_exename (__banning_exename, LSR_MAXPATHLEN);
	__banning_exename[LSR_MAXPATHLEN-1] = '\0';
#ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: __lsr_check_prog_ban(): exename='%s'\n",
		__banning_exename);
	fflush (stderr);
#endif

	if ( __banning_exename[0] == '\0' /*strlen (__banning_exename) == 0*/ )
	{
		/* can't find executable name. Assume not banned */
		__lsr_set_internal_function (0);
		LSR_SET_ERRNO (err);
		return 0;
	}

	if ( __lsr_real_fopen_location () != NULL )
	{
		ret = __banning_is_banned ("libsecrm.progban",
			LSR_PROG_BANNING_USERFILE, LSR_PROG_BANNING_ENV,
			__banning_exename);
	}
	__lsr_set_internal_function (0);
#ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: __lsr_check_prog_ban()=%d\n", ret);
	fflush (stderr);
#endif
	LSR_SET_ERRNO (err);

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
		LSR_MEMSET (__lsr_linkpath, 0, j);
		__lsr_copy_string (__lsr_linkpath, name, j-1);
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
				LSR_MEMSET (__lsr_newlinkpath, 0, (size_t)lsize);
				res = readlink (__lsr_linkpath, __lsr_newlinkpath,
					(size_t)lsize);
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
				__lsr_copy_string (__lsr_linkpath, __lsr_newlinkpath,
					(size_t)res);
# endif
			}
			else
			{
				break;
			}
			res = lstat (__lsr_linkpath, &st);
		}
#endif /* (defined HAVE_SYS_STAT_H) && (defined HAVE_READLINK) && (defined HAVE_LSTAT) */
		for ( j = 0; j < sizeof (__lsr_valuable_files)/sizeof (__lsr_valuable_files[0]); j++)
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
	LSR_MAKE_ERRNO_VAR(err);

#ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: __lsr_check_file_ban(%s)\n",
		(name != NULL)? name : "null");
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
		ret = __banning_is_banned ("libsecrm.fileban",
			LSR_FILE_BANNING_USERFILE, LSR_FILE_BANNING_ENV,
			name);
	}
	__lsr_set_internal_function (0);
#ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: __lsr_check_file_ban(%s)=%d\n",
		(name != NULL)? name : "null", ret);
	fflush (stderr);
#endif
	LSR_SET_ERRNO (err);

	return ret;
}

/* ======================================================= */

/**
 * Checks if the given object can be wiped (name not banned, program not
 *	banned, object type is correct).
 * @return non-zero if the given object can be wiped.
 */
int GCC_WARN_UNUSED_RESULT
__lsr_can_wipe_filename (
#ifdef LSR_ANSIC
	const char * const name)
#else
	name)
	const char * const name;
#endif
{
#ifdef HAVE_SYS_STAT_H
	struct stat s;
#endif

	if ( name == NULL )
	{
		return 0;
	}

	if ( name[0] == '\0' /*strlen (name) == 0*/ )
	{
		return 0;
	}

#if (!defined HAVE_SYS_STAT_H) || (!defined HAVE_LSTAT)
	/* Sorry, can't truncate something I can't lstat().
	This would cause problems. */
	return 0;
#else
	/* NOTE: stat() may be dangerous. If a filesystem has symbolic links,
	   but lstat() is unavailable, stat() returns information about the
	   target of the link. The link itself will be removed, but it's the
	   target of the link that would be wiped. This is why we either use
	   lstat() or quit.
	*/
	if ( lstat (name, &s) == 0 )
	{
		/* don't operate on non-directories */
		if ( ! S_ISREG (s.st_mode) )
		{
			return 0;
		}
	}
	else
	{
		return 0;
	}
#endif

	if ( (__lsr_check_prog_ban () != 0)
		|| (__lsr_check_file_ban (name) != 0)
		|| (__lsr_check_file_ban_proc (name) != 0) )
	{
		return 0;
	}
	return 1;
}

/* ======================================================= */

/**
 * Checks if the given object can be wiped (name not banned, program not
 *	banned, object type is correct).
 * @return non-zero if the given object can be wiped.
 */
int GCC_WARN_UNUSED_RESULT
__lsr_can_wipe_filename_atdir (
#ifdef LSR_ANSIC
	const char * const name, const int dir_fd)
#else
	name, dir_fd)
	const char * const name;
	const int dir_fd;
#endif
{
#ifdef HAVE_SYS_STAT_H
	struct stat s;
#endif

	if ( name == NULL )
	{
		return 0;
	}

	if ( name[0] == '\0' /*strlen (name) == 0*/ )
	{
		return 0;
	}

#if (!defined HAVE_SYS_STAT_H) || (!defined HAVE_FSTATAT)
	/* Sorry, can't truncate something I can't fstatat().
	This would cause problems. */
	return 0;
#else
	if ( fstatat (dir_fd, name, &s, AT_SYMLINK_NOFOLLOW) == 0 )
	{
		/* don't operate on non-directories */
		if ( ! S_ISREG (s.st_mode) )
		{
			return 0;
		}
	}
	else
	{
		return 0;
	}
#endif

	if ( (__lsr_check_prog_ban () != 0)
		|| (__lsr_check_file_ban (name) != 0)
		|| (__lsr_check_file_ban_proc (name) != 0) )
	{
		return 0;
	}
	return 1;
}

/* ======================================================= */

/**
 * Checks if the given file descriptor can be wiped (name not banned, program not
 *	banned, object type is correct).
 * @return non-zero if the given file descriptor can be wiped.
 */
int GCC_WARN_UNUSED_RESULT
__lsr_can_wipe_filedesc (
#ifdef LSR_ANSIC
	const int fd)
#else
	fd)
	const int fd;
#endif
{
#ifdef HAVE_SYS_STAT_H
	struct stat s;
#endif

#if (!defined HAVE_SYS_STAT_H) || (!defined HAVE_FSTAT)
	/* Sorry, can't truncate something I can't fstat().
	This would cause problems. */
	return 0;
#else
	if ( fstat (fd, &s) == 0 )
	{
		/* don't operate on non-files */
		if ( ! S_ISREG (s.st_mode) )
		{
			return 0;
		}
	}
	else
	{
		return 0;
	}
#endif
	if ( __lsr_check_prog_ban () != 0
		/* don't have any names to check here */ )
	{
		return 0;
	}
	return 1;
}
