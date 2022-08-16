/*
 * A library for secure removing files.
 *	-- unit test for banning functions.
 *
 * Copyright (C) 2019-2021 Bogdan Drozdowski, bogdro (at) users . sourceforge . net
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

#define _POSIX_C_SOURCE 200112L	/* posix_memalign() */
#define _XOPEN_SOURCE 600	/* brk(), sbrk() */
#define _LARGEFILE64_SOURCE 1	/* off64_t in libsecrm-priv.h */
#define _GNU_SOURCE	1	/* fallocate() */
#define _ATFILE_SOURCE 1
#define _GNU_SOURCE	1
#define _DEFAULT_SOURCE
#define _ISOC11_SOURCE		/* aligned_alloc() */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#if (defined HAVE_DLFCN_H) && ((defined HAVE_DLSYM) || (defined HAVE_LIBDL))
	/* need RTLD_NEXT and dlvsym(), so define _GNU_SOURCE */
# ifndef _GNU_SOURCE
#  define _GNU_SOURCE	1
# endif
# include <dlfcn.h>
# ifndef RTLD_NEXT
#  define RTLD_NEXT ((void *) -1l)
# endif
#else
# ifdef LSR_ANSIC
#  error Dynamic loading functions missing.
# endif
#endif

#include "libsecrm.h"
#include <check.h>
#include "lsrtest_common.h"

#ifdef HAVE_ERRNO_H
# include <errno.h>
#else
static int errno = -1;
#endif

#ifdef HAVE_MALLOC_H
# include <malloc.h>
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#include <stdio.h>

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif

#ifdef HAVE_STRING_H
# if (!defined STDC_HEADERS) && (defined HAVE_MEMORY_H)
#  include <memory.h>
# endif
# include <string.h>
#endif

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#else
# define O_RDONLY	0
# define O_WRONLY	1
# define O_RDWR		2
# define O_TRUNC	01000
#endif

#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#else
# define S_IRUSR 0600
# define S_IWUSR 0400
#endif

/* ======================================================= */

static int prepare_ban_file (const char filename[], const char contents[],
	char ** const user_ban_file_name, long * const file_len)
{
	FILE * user_ban_file;
	char * home_env;
	int err;
	size_t ban_file_name_len;

	if ( filename == NULL || contents == NULL || user_ban_file_name == NULL
		|| file_len == NULL )
	{
		fail("prepare_ban_file: invalid parameters\n");
	}
	home_env = getenv("HOME");
	if ( home_env == NULL )
	{
		fail("prepare_ban_file: cannot get the home directory\n");
	}
	ban_file_name_len = strlen (home_env) + 1
		+ strlen (filename) + 1;
	*user_ban_file_name = (char *) malloc (ban_file_name_len);
	if ( *user_ban_file_name == NULL )
	{
		fail("prepare_ban_file: cannot allocate memory: errno=%d\n", errno);
	}
	strcpy (*user_ban_file_name, home_env);
	strcat (*user_ban_file_name, "/");
	strcat (*user_ban_file_name, filename);
	(*user_ban_file_name)[ban_file_name_len - 1] = '\0';

	user_ban_file = fopen (*user_ban_file_name, "a+");
	if ( user_ban_file == NULL )
	{
		err = errno;
		free (*user_ban_file_name);
		*user_ban_file_name = NULL;
		fail("prepare_ban_file: cannot open user file: errno=%d\n", err);
	}

	lsrtest_set_inside_write (1);
	fseek (user_ban_file, 0, SEEK_END);
	*file_len = ftell (user_ban_file);
	fwrite (contents, 1, strlen(contents), user_ban_file);
	fclose (user_ban_file);
	lsrtest_set_inside_write (0);
	lsrtest_set_nwritten (0);
	lsrtest_set_nwritten_total (0);

	return 0;
}

static int prepare_env_ban_file (const char filename[], const char contents[],
	const char env_var_name[], long * const file_len)
{
	FILE * env_ban_file;
	int res;

	if ( filename == NULL || contents == NULL
		|| file_len == NULL )
	{
		fail("prepare_env_ban_file: invalid parameters\n");
	}
	res = setenv(env_var_name, filename, 1);
	if ( res != 0 )
	{
		fail("test_banned_in_env_prog: cannot set environment: errno=%d\n", errno);
	}

	env_ban_file = fopen (filename, "a+");
	if ( env_ban_file == NULL )
	{
		fail("test_banned_in_env_prog: cannot open user file: errno=%d\n", errno);
	}

	lsrtest_set_inside_write (1);
	fseek (env_ban_file, 0, SEEK_END);
	*file_len = ftell (env_ban_file);
	fwrite (contents, 1, strlen(contents), env_ban_file);
	fclose (env_ban_file);
	lsrtest_set_inside_write (0);
	lsrtest_set_nwritten (0);
	lsrtest_set_nwritten_total (0);

	return 0;
}

/* ======================================================= */

#ifdef LSR_CAN_USE_BANS
START_TEST(test_banned_in_userfile_prog)
{
	int fd;
	char * user_ban_file_name = NULL;
	int err;
	long file_len;
	size_t nwritten;

	LSR_PROLOG_FOR_TEST();

	if ( prepare_ban_file (LSR_PROG_BANNING_USERFILE,
		"\nlsrtest\n", &user_ban_file_name, &file_len) != 0 )
	{
		return;
	}

	fd = open(LSR_TEST_FILENAME, O_WRONLY | O_TRUNC);
	nwritten = lsrtest_get_nwritten ();
	err = errno;
	if ( file_len == 0 )
	{
fprintf(stderr, "Will unlink '%s'\n", user_ban_file_name);
		unlink (user_ban_file_name);
	}
	else
	{
		truncate (user_ban_file_name, file_len);
	}
	if (fd >= 0)
	{
		close(fd);
	}
	else
	{
		free (user_ban_file_name);
		fail("test_banned_in_userfile_prog: file not opened: errno=%d\n", err);
	}
	free (user_ban_file_name);
	ck_assert_int_eq((int) nwritten, 0);
}
END_TEST

START_TEST(test_banned_in_userfile_file)
{
	int fd;
	char * user_ban_file_name = NULL;
	int err;
	long file_len;
	size_t nwritten;

	LSR_PROLOG_FOR_TEST();

	if ( prepare_ban_file (LSR_FILE_BANNING_USERFILE,
		"\n" LSR_TEST_FILENAME "\n", &user_ban_file_name, &file_len) != 0 )
	{
		return;
	}

	fd = open(LSR_TEST_FILENAME, O_WRONLY | O_TRUNC);
	nwritten = lsrtest_get_nwritten ();
	err = errno;
	if ( file_len == 0 )
	{
fprintf(stderr, "Will unlink '%s'\n", user_ban_file_name);
		unlink (user_ban_file_name);
	}
	else
	{
		truncate (user_ban_file_name, file_len);
	}
	if (fd >= 0)
	{
		close(fd);
	}
	else
	{
		free (user_ban_file_name);
		fail("test_banned_in_userfile_file: file not opened: errno=%d\n", err);
	}
	free (user_ban_file_name);
	ck_assert_int_eq((int) nwritten, 0);
}
END_TEST
#endif

#ifdef LSR_CAN_USE_ENV
START_TEST(test_banned_in_env_prog)
{
	int fd;
	char env_ban_file_name[] = "libsecrm.env";
	int err;
	long file_len;
	size_t nwritten;

	LSR_PROLOG_FOR_TEST();

	if ( prepare_env_ban_file (env_ban_file_name,
		"\nlsrtest\n", LSR_PROG_BANNING_ENV, &file_len) != 0 )
	{
		return;
	}

	fd = open(LSR_TEST_FILENAME, O_WRONLY | O_TRUNC);
	nwritten = lsrtest_get_nwritten ();
	err = errno;
	if ( file_len == 0 )
	{
fprintf(stderr, "Will unlink '%s'\n", env_ban_file_name);
		unlink (env_ban_file_name);
	}
	else
	{
		truncate (env_ban_file_name, file_len);
	}
	if (fd >= 0)
	{
		close(fd);
	}
	else
	{
		fail("test_banned_in_env_prog: file not opened: errno=%d\n", err);
	}
	ck_assert_int_eq((int) nwritten, 0);
}
END_TEST

START_TEST(test_banned_in_env_file)
{
	int fd;
	char env_ban_file_name[] = "libsecrm.env";
	int err;
	long file_len;
	size_t nwritten;

	LSR_PROLOG_FOR_TEST();

	if ( prepare_env_ban_file (env_ban_file_name,
		"\n" LSR_TEST_FILENAME "\n", LSR_FILE_BANNING_ENV, &file_len) != 0 )
	{
		return;
	}

	fd = open(LSR_TEST_FILENAME, O_WRONLY | O_TRUNC);
	nwritten = lsrtest_get_nwritten ();
	err = errno;
	if ( file_len == 0 )
	{
fprintf(stderr, "Will unlink '%s'\n", env_ban_file_name);
		unlink (env_ban_file_name);
	}
	else
	{
		truncate (env_ban_file_name, file_len);
	}
	if (fd >= 0)
	{
		close(fd);
	}
	else
	{
		fail("test_banned_in_env_file: file not opened: errno=%d\n", err);
	}
	ck_assert_int_eq((int) nwritten, 0);
}
END_TEST
#endif

/* ======================================================= */

static Suite * lsr_create_suite(void)
{
	Suite * s = suite_create("libsecrm_banning");

	TCase * tests_banned = tcase_create("banning");

#ifdef LSR_CAN_USE_BANS
	tcase_add_test(tests_banned, test_banned_in_userfile_prog);
	tcase_add_test(tests_banned, test_banned_in_userfile_file);
#endif
#ifdef LSR_CAN_USE_ENV
	tcase_add_test(tests_banned, test_banned_in_env_prog);
	tcase_add_test(tests_banned, test_banned_in_env_file);
#endif
	lsrtest_add_fixtures (tests_banned);

	/* set 30-second timeouts */
	tcase_set_timeout(tests_banned, 30);

	suite_add_tcase(s, tests_banned);

	return s;
}

int main(void)
{
	int failed;

	Suite * s = lsr_create_suite();
	SRunner * sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);

	failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return failed;
}
