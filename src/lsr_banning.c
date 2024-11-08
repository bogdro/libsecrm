/*
 * LibSecRm - A library for secure removing files.
 *	-- private file and program banning functions.
 *
 * Copyright (C) 2007-2024 Bogdan Drozdowski, bogdro (at) users . sourceforge . net
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "lsr_cfg.h"

#define _LARGEFILE64_SOURCE 1

/* major, minor, makedev */
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#ifdef HAVE_SYS_SYSMACROS_H
# include <sys/sysmacros.h>
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

#define LSR_IS_CURRENT_DIR(dirent) (NAMLEN(dirent) == 1 && (dirent)->d_name[0] == '.')
#define LSR_IS_PARENT_DIR(dirent) (NAMLEN(dirent) == 2 && (dirent)->d_name[0] == '.' && (dirent)->d_name[1] == '.')

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif

/* time declarations for stat.h with POSIX_C_SOURCE >= 200809L */
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif

#ifdef HAVE_TIME_H
# include <time.h>
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

#ifdef HAVE_LIMITS_H
# include <limits.h>
#endif

#ifdef HAVE_STDLIB_H
# include <stdlib.h>	/* getenv(), realpath() */
#endif

#ifdef HAVE_MALLOC_H
# include <malloc.h>
#endif

#include "lsr_priv.h"
#include "libsecrm.h"
#include "lsr_paths.h"

#ifdef __cplusplus
extern "C" {
#endif

/* in macOS, the 64-bit versions of functions seem to be aliases without declarations */
#if (defined HAVE_FSTATAT64) && ( \
	(defined __DARWIN_C_ANSI) \
	|| (defined __DARWIN_C_FULL) \
	|| (defined __DARWIN_C_LEVEL) /* better than nothing */ \
	)
extern int fstatat64 LSR_PARAMS((int dirfd, const char *restrict pathname,
                struct stat64 *restrict statbuf, int flags));
#endif

#ifdef __cplusplus
}
#endif


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

static const char * __lsr_fragile_filesystems[] =
{
	"/sys", "/proc", "/dev", "/selinux"
};

#if (defined HAVE_SYS_STAT_H) && (	\
	   (defined HAVE_DIRENT_H)	\
	|| (defined HAVE_NDIR_H)	\
	|| (defined HAVE_SYS_DIR_H)	\
	|| (defined HAVE_SYS_NDIR_H)	\
	)
# define LSR_CAN_USE_DIRS 1
# define LSR_UNUSED_WITHOUT_DIRS
#else
# undef LSR_CAN_USE_DIRS
# define LSR_UNUSED_WITHOUT_DIRS LSR_ATTR ((unused))
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

#ifdef TEST_COMPILE
# undef LSR_ANSIC
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
	const char * const dirname, const dev_t objects_fs, const ino_t objects_inode));
# endif

static char __lsr_dirpath[LSR_MAXPATHLEN], __lsr_filepath[LSR_MAXPATHLEN];

/**
 * Browse the given /proc subdirectory to see if a file is listed there as being used.
 * \param pid the current process ID
 * \param dirname the name of the directory to browse
 * \param objects_fs the file's filesystem's device ID
 * \param objects_inode the file's i-node number
 * \return 0 if the object is not banned (not found while browsing the directory)
 */
static int
check_dir (
# ifdef LSR_ANSIC
	const pid_t pid, const char * const dirname,
	const dev_t objects_fs, const ino_t objects_inode)
# else
	pid, dirname, objects_fs, objects_inode)
	const pid_t pid;
	const char * const dirname;
	const dev_t objects_fs;
	const ino_t objects_inode;
# endif
{
	int res = 0;
	DIR * dirp;
	const struct dirent * direntry;
# ifdef HAVE_STAT64
	struct stat64 st_dyn;
# else
#  ifdef HAVE_STAT
	struct stat st_dyn;
#  endif
# endif

# ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: check_dir(%d, %d, %d)\n", pid, objects_fs, objects_inode);
	fflush (stderr);
# endif

	if ( dirname == NULL )
	{
		/* Can't check - assume not banned for now. This directory
			may simply not exist. */
		return 0;
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
		if ( LSR_IS_CURRENT_DIR(direntry) || LSR_IS_PARENT_DIR(direntry) )
		{
			continue;
		}

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
#  ifdef HAVE_STAT64
		if (stat64 (__lsr_filepath, &st_dyn) != 0)	/* NOT lstat() ! */
# else
#  ifdef HAVE_STAT
		if (stat (__lsr_filepath, &st_dyn) != 0)	/* NOT lstat() ! */
#  else
		if ( 1 )
#  endif
# endif
		{
			/* Just skip it. We may get results like
			"67 -> socket:[13006]", so stat() would fail */
			continue;
		}
		else
		{
			if ( (st_dyn.st_dev == objects_fs)
				&& (st_dyn.st_ino == objects_inode) )
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
	fprintf (stderr, "libsecrm: check_dir(%d, %d, %d)=%d\n", pid, objects_fs, objects_inode, res);
	fflush (stderr);
# endif

	closedir (dirp);
	return res;
}
#endif	/* LSR_CAN_USE_DIRS */

/* ======================================================= */

#if (defined LSR_CAN_USE_DIRS) && ((defined HAVE_SYS_TYPES_H) || (defined HAVE_SYS_SYSMACROS_H)	\
	|| (defined MAJOR_IN_MKDEV) || (defined MAJOR_IN_SYSMACROS))

# ifndef LSR_ANSIC
static int check_map LSR_PARAMS((const pid_t pid, const char * const dirname,
	const dev_t objects_fs, const ino_t objects_inode));
# endif

# define LSR_BUFSIZ LSR_MAXPATHLEN
static char __lsr_pathname[LSR_MAXPATHLEN];
/*static char __lsr_dummy[LSR_MAXPATHLEN];*/
static char __lsr_line[LSR_BUFSIZ];

/**
 * Browse the given /proc memory map to see if a file is listed there as being used.
 * \param pid the current process ID
 * \param dirname the name of the directory to browse
 * \param objects_fs the file's filesystem's device ID
 * \param objects_inode the file's i-node number
 * \return 0 if the object is not banned (not found while browsing the directory)
 */
static int
check_map (
# ifdef LSR_ANSIC
	const pid_t pid, const char * const dirname,
	const dev_t objects_fs, const ino_t objects_inode)
# else
	pid, dirname, objects_fs, objects_inode)
	const pid_t pid;
	const char * const dirname;
	const dev_t objects_fs;
	const ino_t objects_inode;
# endif
{
	int res = 0;
	FILE *fp;
	union u
	{
# ifdef HAVE_LONG_LONG_INT
		unsigned long long int ll;
# else
		unsigned long int ll;
# endif
		ino_t tmp_inode;
	} tmp_inode;
	unsigned int tmp_maj, tmp_min;

# ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: check_map(%d, %d, %d)\n", pid, objects_fs, objects_inode);
	fflush (stderr);
# endif

	if ( dirname == NULL )
	{
		/* Can't check - assume not banned for now. This directory
			may simply not exist. */
		return 0;
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
			tmp_inode.ll = 0;
			if ( sscanf (__lsr_line,
# ifdef HAVE_LONG_LONG_INT
				/*if ( sscanf (__lsr_line, "%s %s %s %x:%x %llu",
					__lsr_dummy, __lsr_dummy, __lsr_dummy,
					&tmp_maj, &tmp_min, &tmp_inode.ll) == 6 )*/
				"%*s %*s %*s %x:%x %llu",
# else
				/*if ( sscanf (__lsr_line, "%s %s %s %x:%x %lu",
					__lsr_dummy, __lsr_dummy, __lsr_dummy,
					&tmp_maj, &tmp_min, &tmp_inode.ll) == 6 )*/
				"%*s %*s %*s %x:%x %lu",
# endif
				&tmp_maj, &tmp_min, &tmp_inode.ll) == 3 )
			{
				if ( (objects_fs == makedev (tmp_maj, tmp_min))
					&& (objects_inode == tmp_inode.tmp_inode)
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
	fprintf (stderr, "libsecrm: check_map(%d, %d, %d)=%d\n", pid, objects_fs, objects_inode, res);
	fflush (stderr);
# endif

	return res;
}
#endif /* (defined LSR_CAN_USE_DIRS) && ((defined HAVE_SYS_TYPES_H)	\
	|| (defined MAJOR_IN_MKDEV) || (defined MAJOR_IN_SYSMACROS)) */


/* ======================================================= */

#ifndef LSR_ANSIC
static int GCC_WARN_UNUSED_RESULT
__lsr_check_file_ban_proc LSR_PARAMS((const dev_t objects_fs, const ino_t objects_inode));
#endif

/**
 * Check if the given file is opened by browsing /proc.
 * \param objects_fs the file's filesystem's device ID
 * \param objects_inode the file's i-node number
 * \return 0 if the object is not banned
 */
static int GCC_WARN_UNUSED_RESULT
__lsr_check_file_ban_proc (
#ifdef LSR_ANSIC
	const dev_t objects_fs LSR_UNUSED_WITHOUT_DIRS,
	const ino_t objects_inode LSR_UNUSED_WITHOUT_DIRS)
#else
	objects_fs, objects_inode)
	const dev_t objects_fs LSR_UNUSED_WITHOUT_DIRS;
	const ino_t objects_inode LSR_UNUSED_WITHOUT_DIRS;
#endif
{
	LSR_MAKE_ERRNO_VAR(err);
	int res = 0;
#ifdef LSR_CAN_USE_DIRS
	DIR * topproc_dir;
	struct dirent * topproc_dent;
	pid_t pid;
	pid_t my_pid;

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
		if ( LSR_IS_CURRENT_DIR(topproc_dent) || LSR_IS_PARENT_DIR(topproc_dent) )
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
		res += check_dir (pid, "lib" , objects_fs, objects_inode);
		if ( res != 0 )
		{
			break;
		}
		res += check_dir (pid, "mmap", objects_fs, objects_inode);
		if ( res != 0 )
		{
			break;
		}
		res += check_dir (pid, "fd"  , objects_fs, objects_inode);
		if ( res != 0 )
		{
			break;
		}
#if (defined LSR_CAN_USE_DIRS) && ((defined HAVE_SYS_TYPES_H) || (defined HAVE_SYS_SYSMACROS_H)	\
	|| (defined MAJOR_IN_MKDEV) || (defined MAJOR_IN_SYSMACROS))
		res += check_map (pid, "maps", objects_fs, objects_inode);
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
	fprintf (stderr, "libsecrm: __lsr_check_file_ban_proc(%d, %d)=%d\n",
		objects_fs, objects_inode, res);
	fflush (stderr);
#endif
	LSR_SET_ERRNO (err);

	return res;
}


/******************* some of what's below comes from libsafe ***************/

/* ======================================================= */

/**
 * Checks if the current program is banned from LibSecRm (shouldn't be messed with).
 * \return non-zero if the current program is banned from LibSecRm.
 */
int GCC_WARN_UNUSED_RESULT
__lsr_check_prog_ban (LSR_VOID)
{
	int ret = 0;	/* DEFAULT: NO, this program is not banned */
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

	ret = __banning_is_banned ("libsecrm.progban",
		LSR_PROG_BANNING_USERFILE, LSR_PROG_BANNING_ENV,
		__banning_exename, __lsr_real_fopen_location());
	__lsr_set_internal_function (0);
#ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: __lsr_check_prog_ban()=%d\n", ret);
	fflush (stderr);
#endif
	LSR_SET_ERRNO (err);

	return ret;
}

/* ======================================================= */

#ifndef LSR_ANSIC
static int __lsr_is_forbidden_fs LSR_PARAMS((const dev_t fs_dev));
#endif

/**
 * Tells if objects on the filesystem with the given device ID are forbidden to be wiped.
 * \param fs_dev The filesystem's device ID.
 * \return 1 if forbidden, 0 otherwise.
 */
static int __lsr_is_forbidden_fs (
#ifdef LSR_ANSIC
	const dev_t fs_dev)
#else
	fs_dev)
	const dev_t fs_dev;
#endif
{
	size_t j;
#ifdef HAVE_SYS_STAT_H
# ifdef HAVE_STAT64
	struct stat64 s;
# else
#  ifdef HAVE_STAT
	struct stat s;
#  endif
# endif
	for ( j = 0; j < sizeof (__lsr_fragile_filesystems)/sizeof (__lsr_fragile_filesystems[0]); j++)
	{
		/* the results could be cached, but better to do this each
		 * time, in case the filesystem wasn't mounted at init
		 * time or was remounted later
		 */
# ifdef HAVE_STAT64
		if ( stat64 (__lsr_fragile_filesystems[j], &s) == 0 )
# else
#  ifdef HAVE_STAT
		if ( stat (__lsr_fragile_filesystems[j], &s) == 0 )
#  else
		if ( 0 )
#  endif
# endif
		{
			if ( s.st_dev == fs_dev )
			{
				return 1;
			}
		}
	}
#endif
	return 0;
}

/* ======================================================= */

#ifndef LSR_ANSIC
static int __lsr_check_forbidden_file_name LSR_PARAMS((const char * const name));
#endif

/**
 * Tells if the file with the given name is on the forbidden list.
 * \param name The name of the file to check.
 * \return 1 if forbidden, 0 otherwise.
 */
static int __lsr_check_forbidden_file_name (
#ifdef LSR_ANSIC
	const char * const name)
#else
	name)
	const char * const name;
#endif
{
	long int res;
#ifdef HAVE_SYS_STAT_H
# ifdef HAVE_LSTAT64
	struct stat64 st;
# else
#  ifdef HAVE_LSTAT
	struct stat st;
#  endif
# endif
#endif
	char * last_slash;
	size_t dirname_len;
	unsigned long int j;

	if ( name == NULL )
	{
		/* don't operate on unknown objects */
		return 1;
	}
#ifdef HAVE_LSTAT64
	res = lstat64 (name, &st);
#else
# ifdef HAVE_LSTAT
	res = lstat (name, &st);
# else
	res = -1;
# endif
#endif
	if ( res != 0 )
	{
		/* don't operate on unknown objects */
		return 1;
	}

	if ( (! S_ISREG (st.st_mode)) && (! S_ISDIR (st.st_mode)) )
	{
		/* don't operate on non-regular objects */
		return 1;
	}

	/*
	 * BUG in glibc (2.30?) or gcc - when not run with
	 * -Os, rindex/strrchr reaches outside of the buffer.
	 * glibc-X/sysdeps/x86_64/multiarch/strchr-sse2-no-bsf.S?
	 */
	/*last_slash = rindex (name, '/');*/
	last_slash = strrchr (name, '/');
	if ( last_slash != NULL )
	{
		dirname_len = (size_t)(last_slash - name);
	}
	else
	{
		dirname_len = 0;
	}
	for ( j = 0; j < sizeof (__lsr_valuable_files)/sizeof (__lsr_valuable_files[0]); j++)
	{
		/* compare only the file's base name, not the whole path here: */
		if ( strstr (&name[dirname_len], __lsr_valuable_files[j]) != NULL )
		{
			return 1;
		}
	}
	for ( j = 0; j < sizeof (__lsr_fragile_filesystems)/sizeof (__lsr_fragile_filesystems[0]); j++)
	{
		if ( strstr (name, __lsr_fragile_filesystems[j]) == name )
		{
			/* filename begins with a forbidden filesystem's name - banned */
			return 1;
		}
	}
	return 0;
}

/* ======================================================= */

#ifndef LSR_ANSIC
static int __lsr_is_forbidden_file LSR_PARAMS((const char * const name));
#endif

/**
 * Tells if the file with the given name is forbidden to be wiped.
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
	long int res;
	off_t lsize;
# ifdef HAVE_STAT64
	struct stat64 st;
# else
#  ifdef HAVE_STAT
	struct stat st;
#  endif
# endif
# ifdef HAVE_MALLOC
	char * __lsr_newlinkpath;
	char * __lsr_newlinkdir;
# endif
	char * last_slash;
	size_t dirname_len;
#endif
	unsigned long int j;
	int ret = 0;

	if ( name == NULL )
	{
		return 0;
	}
#ifdef HAVE_MALLOC
# ifdef HAVE_CANONICALIZE_FILE_NAME
	__lsr_linkpath = canonicalize_file_name (name);
	if ( __lsr_linkpath != NULL )
	{
		ret = __lsr_check_forbidden_file_name (__lsr_linkpath);
		free (__lsr_linkpath);
		return ret;
	}
# endif
# ifdef HAVE_REALPATH
	__lsr_linkpath = realpath (name, NULL);
	if ( __lsr_linkpath != NULL )
	{
		ret = __lsr_check_forbidden_file_name (__lsr_linkpath);
		free (__lsr_linkpath);
		return ret;
	}
# endif

	/* find the real path manually: */
	j = strlen (name) + 1;
	__lsr_linkpath = (char *) malloc ( j );
	if ( __lsr_linkpath != NULL )
#endif
	{
#ifndef HAVE_MALLOC
		j = sizeof (__lsr_linkpath);
#endif
		LSR_MEMSET (__lsr_linkpath, 0, j);
		__lsr_copy_string (__lsr_linkpath, name, j-1);
#if (defined HAVE_SYS_STAT_H) && (defined HAVE_READLINK)
# ifdef HAVE_LSTAT64
		res = lstat64 (name, &st);
# else
#  ifdef HAVE_LSTAT
		res = lstat (name, &st);
#  else
		res = -1;
#  endif
# endif
		while ( res >= 0 )
		{
			if ( ! S_ISLNK (st.st_mode) )
			{
				break;
			}
			lsize = st.st_size;
			if ( lsize <= 0 )
			{
				break;
			}
			/* in case the link's target is a relative path,
			prepare to prepend the link's directory name */
			/*
			 * BUG in glibc (2.30?) or gcc - when not run with
			 * -Os, rindex/strrchr reaches outside of the buffer.
			 * glibc-X/sysdeps/x86_64/multiarch/strchr-sse2-no-bsf.S?
			 */
			/*last_slash = rindex (__lsr_linkpath, '/');*/
			last_slash = strrchr (__lsr_linkpath, '/');
			if ( last_slash != NULL )
			{
				dirname_len = (size_t)(last_slash - __lsr_linkpath);
			}
			else
			{
				dirname_len = 0;
			}
# ifdef HAVE_MALLOC
			__lsr_newlinkpath = (char *) malloc ((size_t)(
				dirname_len + 1
				+ (size_t)lsize + 1));
			if ( __lsr_newlinkpath == NULL )
			{
				break;
			}
			LSR_MEMSET (__lsr_newlinkpath, 0, (size_t)(
				dirname_len + 1
				+ (size_t)lsize + 1));
# else /* ! HAVE_MALLOC */
			LSR_MEMSET (__lsr_newlinkpath, 0, sizeof (__lsr_newlinkpath));
# endif /* HAVE_MALLOC */
			res = readlink (__lsr_linkpath, __lsr_newlinkpath,
				(size_t)lsize);
			if ( (res < 0) || (res > lsize) )
			{
# ifdef HAVE_MALLOC
				free (__lsr_newlinkpath);
# endif /* HAVE_MALLOC */
				break;
			}
			__lsr_newlinkpath[res] = '\0';
			if ( (__lsr_newlinkpath[0] != '/') && (dirname_len > 0) )
			{
				/* The link's target is a relative path (no slash) in a
				different directory (there was a slash in the original path)
				- append the link's directory name */
# ifdef HAVE_MALLOC
				__lsr_newlinkdir = (char *) malloc ((size_t)(
					dirname_len + 1
					+ (size_t)lsize + 1));
				if ( __lsr_newlinkdir == NULL )
				{
					free (__lsr_newlinkpath);
					break;
				}
# endif /* HAVE_MALLOC */
				strncpy (__lsr_newlinkdir, __lsr_linkpath, dirname_len);
				__lsr_newlinkdir[dirname_len] = '/';
				__lsr_newlinkdir[dirname_len + 1] = '\0';
				strncat (__lsr_newlinkdir, __lsr_newlinkpath,
					(size_t)lsize + 1);
				__lsr_newlinkdir[dirname_len + 1
					+ (size_t)lsize] = '\0';
				__lsr_copy_string(__lsr_newlinkpath, __lsr_newlinkdir,
					dirname_len + 1 + (size_t)lsize + 1);
# ifdef HAVE_MALLOC
				free (__lsr_newlinkdir);
# endif /* HAVE_MALLOC */
			}
			res = strcmp (__lsr_linkpath, __lsr_newlinkpath);
# ifdef HAVE_MALLOC
			free (__lsr_linkpath);
			__lsr_linkpath = __lsr_newlinkpath;
# else
			__lsr_copy_string (__lsr_linkpath, __lsr_newlinkpath,
				(size_t)res+1);
# endif
			if ( res == 0 )
			{
				/* the old and new names are the same - a link pointing to itself */
				break;
			}
# ifdef HAVE_LSTAT64
			res = lstat64 (__lsr_linkpath, &st);
# else
#  ifdef HAVE_LSTAT
			res = lstat (__lsr_linkpath, &st);
#  else
			res = -1;
#  endif
# endif
		}
#endif /* (defined HAVE_SYS_STAT_H) && (defined HAVE_READLINK) */
		ret = __lsr_check_forbidden_file_name (__lsr_linkpath);
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

#ifndef LSR_ANSIC
static int __lsr_is_forbidden_fd
	LSR_PARAMS ((const int fd));
#endif

/**
 * Tells if the file with the given file descriptor is forbidden to be wiped.
 * \param fd The file descriptor to check.
 * \return 1 if forbidden, 0 otherwise.
 */
static int __lsr_is_forbidden_fd (
#ifdef LSR_ANSIC
	const int fd)
#else
	fd)
	const int fd;
#endif
{
	/* strlen(/proc) + strlen(/self) + strlen(/fd/) + strlen(maxint) + '\0' */
	char linkpath[5 + 5 + 4 + 11 + 1];

	if ( fd < 0 )
	{
		return 0;
	}
#ifdef HAVE_SNPRINTF
	snprintf (linkpath, sizeof(linkpath) - 1, "/proc/self/fd/%d", fd);
#else
	sprintf (linkpath, "/proc/self/fd/%d", fd);
#endif
	linkpath[sizeof(linkpath) - 1] = '\0';
	return __lsr_is_forbidden_file (linkpath);
}

/* ======================================================= */

#ifndef LSR_ANSIC
static int GCC_WARN_UNUSED_RESULT
__lsr_check_file_ban LSR_PARAMS((const char * const name));
#endif

/**
 * Checks if the given file is banned from LibSecRm (shouldn't be messed with).
 * \param name The name of the file to check.
 * \return non-zero if the given file is banned from LibSecRm.
 */
static int GCC_WARN_UNUSED_RESULT
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

	if ( ret == 0 )
	{
		ret = __banning_is_banned ("libsecrm.fileban",
			LSR_FILE_BANNING_USERFILE, LSR_FILE_BANNING_ENV,
			name, __lsr_real_fopen_location());
	}
	__lsr_set_internal_function (0);
#ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: __lsr_check_file_ban(%s)=%d\n", name, ret);
	fflush (stderr);
#endif
	LSR_SET_ERRNO (err);

	return ret;
}

/* ======================================================= */

/**
 * Checks if the given object can be wiped (name not banned, program not
 *	banned, object type is correct).
 * \param name The name of the file to check.
 * \param follow_links if non-zero, stat() will be used to check the target
 * 	object (useful for open() etc.). If zero, lstat() will be used to
 * 	check the given path (useful for unlink() etc.).
 * \return non-zero if the given object can be wiped.
 */
int GCC_WARN_UNUSED_RESULT
__lsr_can_wipe_filename (
#ifdef LSR_ANSIC
	const char * const name, const int follow_links)
#else
	name, follow_links)
	const char * const name;
	const int follow_links;
#endif
{
#ifdef HAVE_SYS_STAT_H
# ifdef HAVE_STAT64
	struct stat64 s;
# else
#  ifdef HAVE_STAT
	struct stat s;
#  endif
# endif
	int res = -1;
#endif

	if ( name == NULL )
	{
		return 0;
	}

	if ( name[0] == '\0' /*strlen (name) == 0*/ )
	{
		return 0;
	}

#if (!defined HAVE_SYS_STAT_H)
	/* Sorry, can't truncate something I can't stat() or lstat().
	This would cause problems. */
	return 0;
#else
	/* NOTE: stat() may be dangerous. If a filesystem has symbolic links,
	   but lstat() is unavailable, stat() returns information about the
	   target of the link. The link itself will be removed, but it's the
	   target of the link that would be wiped. This is why we either use
	   lstat() or quit.
	*/
	if ( follow_links == 1 )
	{
# ifdef HAVE_STAT64
		res = stat64 (name, &s);
# else
#  ifdef HAVE_STAT
		res = stat (name, &s);
#  else
		res = 1;
#  endif
# endif
	}
	else
	{
# ifdef HAVE_LSTAT64
		res = lstat64 (name, &s);
# else
#  ifdef HAVE_LSTAT
		res = lstat (name, &s);
#  else
		res = 1;
#  endif
# endif
	}
	if ( res != 0 )
	{
		/* can't stat()  - don't wipe */
		return 0;
	}
	if ( ! S_ISREG (s.st_mode) )
	{
		/* don't operate on non-regular objects */
		return 0;
	}

	if ( (__lsr_check_prog_ban () != 0)
		|| (__lsr_check_file_ban (name) != 0)
		|| (__lsr_is_forbidden_fs (s.st_dev) != 0)
		|| (__lsr_check_file_ban_proc (s.st_dev, s.st_ino) != 0) )
	{
		return 0;
	}
	return 1;
#endif
}

/* ======================================================= */

/**
 * Checks if the given object can be wiped (name not banned, program not
 *	banned, object type is correct).
 * @param name a name of a directory to wipe.
 * @return non-zero if the given object can be wiped.
 */
int GCC_WARN_UNUSED_RESULT
__lsr_can_wipe_dirname (
#ifdef LSR_ANSIC
	const char * const name)
#else
	name)
	const char * const name;
#endif
{
#ifdef HAVE_SYS_STAT_H
# ifdef HAVE_STAT64
	struct stat64 s;
# else
#  ifdef HAVE_STAT
	struct stat s;
#  endif
# endif
#endif

	if ( name == NULL )
	{
		return 0;
	}

	if ( name[0] == '\0' /*strlen (name) == 0*/ )
	{
		return 0;
	}

#if (!defined HAVE_SYS_STAT_H)
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
# ifdef HAVE_LSTAT64
	if ( lstat64 (name, &s) == 0 )
# else
#  ifdef HAVE_LSTAT
	if ( lstat (name, &s) == 0 )
#  else
	if ( 0 )
#  endif
# endif
	{
		/* don't operate on non-directories */
		if ( ! S_ISDIR (s.st_mode) )
		{
			return 0;
		}
	}
	else
	{
		return 0;
	}

	if ( (__lsr_check_prog_ban () != 0)
		|| (__lsr_check_file_ban (name) != 0)
		|| (__lsr_is_forbidden_fs (s.st_dev) != 0)
		|| (__lsr_check_file_ban_proc (s.st_dev, s.st_ino) != 0) )
	{
		return 0;
	}
	return 1;
#endif
}

/* ======================================================= */

/**
 * Checks if the given object can be wiped (name not banned, program not
 *	banned, object type is correct).
 * @param name a name of an object to wipe.
 * @param dir_fd a descriptor of a directory containing the object to wipe.
 * \param follow_links if non-zero, fstatat() will be used to check the target
 * 	object (useful for open() etc.). If zero, fstatat() with
 *	AT_SYMLINK_NOFOLLOW will be used to check the given path (useful for
 * 	unlink() etc.).
 * @return non-zero if the given object can be wiped.
 */
int GCC_WARN_UNUSED_RESULT
__lsr_can_wipe_filename_atdir (
#ifdef LSR_ANSIC
	const char * const name, const int dir_fd, const int follow_links)
#else
	name, dir_fd, follow_links)
	const char * const name;
	const int dir_fd;
	const int follow_links;
#endif
{
#ifdef HAVE_SYS_STAT_H
# ifdef HAVE_STAT64
	struct stat64 s;
# else
#  ifdef HAVE_STAT
	struct stat s;
#  endif
# endif
	int fstatat_flags = 0;
#endif

	if ( name == NULL )
	{
		return 0;
	}

	if ( name[0] == '\0' /*strlen (name) == 0*/ )
	{
		return 0;
	}

#if (!defined HAVE_SYS_STAT_H)
	/* Sorry, can't truncate something I can't fstatat().
	This would cause problems. */
	return 0;
#else
	if ( follow_links == 0 )
	{
		fstatat_flags |= AT_SYMLINK_NOFOLLOW;
	}
# ifdef HAVE_FSTATAT64
	if ( fstatat64 (dir_fd, name, &s, fstatat_flags) == 0 )
# else
#  ifdef HAVE_FSTATAT
	if ( fstatat (dir_fd, name, &s, fstatat_flags) == 0 )
#  else
	if ( 0 )
#  endif
# endif
	{
		/* don't operate on non-regular objects */
		if ( ! S_ISREG (s.st_mode) )
		{
			return 0;
		}
	}
	else
	{
		return 0;
	}

	if ( (__lsr_check_prog_ban () != 0)
		|| (__lsr_check_file_ban (name) != 0)
		|| (__lsr_is_forbidden_fs (s.st_dev) != 0)
		|| (__lsr_check_file_ban_proc (s.st_dev, s.st_ino) != 0) )
	{
		return 0;
	}
	return 1;
#endif
}

/* ======================================================= */

/**
 * Checks if the given file descriptor can be wiped (name not banned, program not
 *	banned, object type is correct).
 * @param fd a file descriptor of an object to wipe.
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
#if (!defined HAVE_SYS_STAT_H)
	/* Sorry, can't truncate something I can't fstat().
	This would cause problems. */
	return 0;
#else
# ifdef HAVE_STAT64
	struct stat64 s;
# else
#  ifdef HAVE_STAT
	struct stat s;
#  endif
# endif
# ifdef HAVE_FSTAT64
	if ( fstat64 (fd, &s) == 0 )
# else
#  ifdef HAVE_FSTAT
	if ( fstat (fd, &s) == 0 )
#  else
	if ( 0 )
#  endif
# endif
	{
		/* The file is already open, so it's not a symlink we'd need
		 * to follow. Just do a regular check - don't operate on non-files: */
		if ( ! S_ISREG (s.st_mode) )
		{
			return 0;
		}
	}
	else
	{
		return 0;
	}

	if ( (__lsr_check_prog_ban () != 0)
		|| (__lsr_is_forbidden_fs (s.st_dev) != 0)
		|| (__lsr_is_forbidden_fd (fd) != 0)
		|| (__lsr_check_file_ban_proc (s.st_dev, s.st_ino) != 0) )
	{
		return 0;
	}
	return 1;
#endif
}
