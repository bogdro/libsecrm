/*
 * LibSecRm, LibHideIP and LibNetBlock.
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

#if (!defined BANNING_ANSIC) \
	 || (!defined HAVE_READLINK) || (!defined BANNING_CAN_USE_BANS) \
	 || (!defined BANNING_ENABLE_ENV) || (!defined HAVE_GETENV)
# error Must include from another file!
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

#ifdef HAVE_STDLIB_H
# include <stdlib.h> /* getenv, malloc */
#else
# ifdef HAVE_MALLOC_H
#  include <malloc.h>
# endif
#endif

static char __banning_exename[BANNING_MAXPATHLEN];	/* 4096 */
static char __banning_omitfile[BANNING_MAXPATHLEN];	/* one line of the banning file */

typedef FILE* (*fopen_pointer)(const char * const name, const char * const mode);

/******************* some of what's below comes from libsafe ***************/

#if !BANNING_ANSIC
static char *
__banning_get_exename BANNING_PARAMS ((char * const exename, const size_t size));
#endif

/**
 * Gets the running program's name and puts in into the given buffer.
 * \param exename The buffer to put into.
 * \param size The size of the buffer.
 * \return The buffer.
 */
static char *
__banning_get_exename (
#if BANNING_ANSIC
	char * const exename, const size_t size)
#else
	exename, size)
	char * const exename;
	const size_t size;
#endif
{
	size_t i;
#if HAVE_READLINK
	ssize_t res;
#endif
	/* strlen(/proc/) + strlen(maxuint or "self") + strlen(/exe) + '\0' */
	char linkpath[6 + 11 + 4 + 1];

	BANNING_MAKE_ERRNO_VAR(err);

	for ( i = 0; i < size; i++ )
	{
		exename[i] = '\0';
	}
	/* get the name of the current executable */
#if HAVE_READLINK
# ifdef HAVE_SNPRINTF
#  ifdef HAVE_GETPID
	snprintf (linkpath, sizeof(linkpath) - 1, "/proc/%d/exe", getpid());
#  else
	strncpy (linkpath, "/proc/self/exe", sizeof(linkpath) - 1);
#  endif
# else
#  ifdef HAVE_GETPID
	sprintf (linkpath, "/proc/%d/exe", getpid());
#  else
	strncpy (linkpath, "/proc/self/exe", sizeof(linkpath) - 1);
#  endif
# endif
	linkpath[sizeof(linkpath) - 1] = '\0';
	res = readlink (linkpath, exename, size - 1);
	if (res == -1)
	{
		exename[0] = '\0';
	}
	else
	{
		if ( (size_t)res < size )
		{
			exename[res] = '\0';
		}
		else
		{
			exename[size-1] = '\0';
		}
	}
#else
	exename[0] = '\0';
#endif
	BANNING_SET_ERRNO (err);

	return exename;
}

/* =============================================================== */

#if !BANNING_ANSIC
static int
__banning_is_banned_in_file BANNING_PARAMS ((
	const char * const exename, const char * const ban_file_name,
	const fopen_pointer fopen_function));
#endif

/**
 * Checks if the given program is banned (listed) in the given file.
 * \param exename The program name to check.
 * \param ban_file_name The name of the banning file to check.
 * \return 0 if not banned, other values otherwise.
 */
static int GCC_WARN_UNUSED_RESULT
__banning_is_banned_in_file (
#if BANNING_ANSIC
	const char * const exename, const char * const ban_file_name,
	const fopen_pointer fopen_function)
#else
	exename, ban_file_name, fopen_function)
	const char * const exename;
	const char * const ban_file_name;
	const fopen_pointer fopen_function;
#endif
{
	FILE *fp;
	int ret = 0;	/* DEFAULT: NO, this program is not banned */
	size_t line_len;
	BANNING_MAKE_ERRNO_VAR(err);

	if ( (exename == NULL) || (ban_file_name == NULL) || (fopen_function == NULL) )
	{
		return ret;
	}

	fp = (* fopen_function) (ban_file_name, "r");
	if ( fp == NULL )
	{
		BANNING_SET_ERRNO (err);
		return ret;
	}
	while ( fgets (__banning_omitfile,
		sizeof (__banning_omitfile), fp) != NULL )
	{
		__banning_omitfile[BANNING_MAXPATHLEN - 1] = '\0';

		do
		{
			line_len = strlen (__banning_omitfile);
			if ( line_len == 0 )
			{
				break;
			}
			if ( (__banning_omitfile[line_len-1] == '\r')
				|| (__banning_omitfile[line_len-1] == '\n') )
			{
				__banning_omitfile[line_len-1] = '\0';
			}
			else
			{
				break;
			}
		}
		while ( line_len != 0 );
		if ( line_len == 0 )
		{
			/* empty line in file */
			continue;
		}
		/*if (strncmp (omitfile, exename, sizeof (omitfile)) == 0)*/
		/* NOTE the reverse parameters */
		/* char *strstr(const char *haystack, const char *needle); */
		if (strstr (exename, __banning_omitfile) != NULL)
		{
			/* needle found in haystack */
			ret = 1;	/* YES, this program is banned */
			break;
		}
	}
	fclose (fp);
	BANNING_SET_ERRNO (err);

	return ret;
}

/* =============================================================== */

#if !BANNING_ANSIC
static int
__banning_is_banned BANNING_PARAMS ((
	const char * const global_banning_filename,
	const char * const user_banning_filename,
	const char * const env_ban_var_name,
	const char * const file_name_to_check,
	const fopen_pointer fopen_function));
#endif

/**
 * Checks if the given program is banned (listed) in the given file.
 * \param global_banning_filename The name of the global banning file.
 * \param user_banning_filename The name of the user banning file.
 * \param env_ban_var_name The name of the environment variable containing the user banning file.
 * \param file_name_to_check The program name to check.
 * \return 0, if the program is not banned.
 */
static int GCC_WARN_UNUSED_RESULT
__banning_is_banned (
#if BANNING_ANSIC
	const char * const global_banning_filename,
	const char * const user_banning_filename,
	const char * const env_ban_var_name,
	const char * const file_name_to_check,
	const fopen_pointer fopen_function)
#else
	global_banning_filename, user_banning_filename,
	env_ban_var_name, file_name_to_check, fopen_function)
	const char * const global_banning_filename;
	const char * const user_banning_filename;
	const char * const env_ban_var_name;
	const char * const file_name_to_check;
	const fopen_pointer fopen_function;
#endif
{
	int ret = 0;
	char * glob_banning_fullname;
	size_t glob_dir_name_len;
	size_t path_sep_len;
	size_t global_banning_filename_len;
#if BANNING_CAN_USE_BANS
	const char *path = NULL;
	char * full_path = NULL;
	size_t path_len;
	size_t filename_len;
	size_t filesep_len;
#endif

	if ( global_banning_filename != NULL )
	{
		glob_dir_name_len = strlen (SYSCONFDIR);
		path_sep_len = strlen (BANNING_PATH_SEP);
		global_banning_filename_len = strlen (global_banning_filename);
		glob_banning_fullname = (char *) malloc (glob_dir_name_len + 1 +
			path_sep_len + 1 + global_banning_filename_len + 1);
		if ( glob_banning_fullname != NULL )
		{
			strncpy (glob_banning_fullname, SYSCONFDIR,
				glob_dir_name_len + 1);
			strncat (glob_banning_fullname, BANNING_PATH_SEP,
				path_sep_len + 1);
			strncat (glob_banning_fullname, global_banning_filename,
				global_banning_filename_len + 1);
			glob_banning_fullname[(glob_dir_name_len + 1 +
			path_sep_len + 1 + global_banning_filename_len + 1) - 1] = '\0';
			ret = __banning_is_banned_in_file (file_name_to_check,
				glob_banning_fullname, fopen_function);
			free (glob_banning_fullname);
		}
	}
#if (BANNING_ENABLE_ENV) && (HAVE_GETENV)
	if ( ret == 0 )
	{
		ret = __banning_is_banned_in_file (file_name_to_check,
			getenv (env_ban_var_name), fopen_function);
	}
#endif
#if BANNING_CAN_USE_BANS
	if ( ret == 0 )
	{
		path = getenv ("HOME");
		if ( path != NULL )
		{
			path_len = strlen (path);
			filename_len = strlen (user_banning_filename);
			filesep_len = strlen (BANNING_PATH_SEP);
			full_path = (char *) malloc (path_len + 1 +
				filesep_len + 1 + filename_len + 1);
			if ( full_path != NULL )
			{
				strncpy (full_path, path, path_len+1);
				strncat (full_path, BANNING_PATH_SEP,
					filesep_len + 1);
				strncat (full_path, user_banning_filename,
					filename_len + 1);
				full_path[(path_len + 1 + filesep_len
					+ 1 + filename_len + 1)-1] = '\0';
				ret = __banning_is_banned_in_file
					(file_name_to_check, full_path, fopen_function);
				free (full_path);
			}
		}
	}
#endif
	return ret;
}
