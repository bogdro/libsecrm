/*
 * A library for secure removing files.
 *	-- unit test for banning functions.
 *
 * Copyright (C) 2019 Bogdan Drozdowski, bogdandr (at) op.pl
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

#ifdef LSR_CAN_USE_BANS
START_TEST(test_banned_in_userfile_prog)
{
	int fd;
	FILE * user_ban_file;
	char * user_ban_file_name;
	char * home_env;
	int err;
	long file_len;
	size_t nwritten;

	lsrtest_set_inside_write (1);
	printf("test_banned_in_userfile_prog\n");
	lsrtest_set_inside_write (0);
	lsrtest_set_nwritten (0);
	lsrtest_set_nwritten_total (0);

	home_env = getenv("HOME");
	if ( home_env == NULL )
	{
		return;
	}
	user_ban_file_name = (char *) malloc (strlen (home_env) + 1
		+ strlen (LSR_PROG_BANNING_USERFILE) + 1);
	if ( user_ban_file_name == NULL )
	{
		fail("test_banned_in_userfile_prog: cannot allocate memory: errno=%d\n", errno);
	}
	strcpy (user_ban_file_name, home_env);
	strcat (user_ban_file_name, "/");
	strcat (user_ban_file_name, LSR_PROG_BANNING_USERFILE);

	user_ban_file = fopen (user_ban_file_name, "a+");
	if ( user_ban_file == NULL )
	{
		err = errno;
		free (user_ban_file_name);
		fail("test_banned_in_userfile_prog: cannot open user file: errno=%d\n", err);
	}

	lsrtest_set_inside_write (1);
	fseek (user_ban_file, 0, SEEK_END);
	file_len = ftell (user_ban_file);
	fwrite ("\nlsrtest\n", 1, strlen("\nlsrtest\n"), user_ban_file);
	fclose (user_ban_file);
	lsrtest_set_inside_write (0);
	lsrtest_set_nwritten (0);
	lsrtest_set_nwritten_total (0);

	fd = open(LSR_TEST_FILENAME, O_WRONLY | O_TRUNC);
	nwritten = lsrtest_get_nwritten ();
	err = errno;
	if ( file_len == 0 )
	{
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
	ck_assert_int_eq(nwritten, 0);
}
END_TEST

START_TEST(test_banned_in_userfile_file)
{
	int fd;
	FILE * user_ban_file;
	char * user_ban_file_name;
	char * home_env;
	int err;
	long file_len;
	size_t nwritten;

	lsrtest_set_inside_write (1);
	printf("test_banned_in_userfile_file\n");
	lsrtest_set_inside_write (0);
	lsrtest_set_nwritten (0);
	lsrtest_set_nwritten_total (0);

	home_env = getenv("HOME");
	if ( home_env == NULL )
	{
		return;
	}
	user_ban_file_name = (char *) malloc (strlen (home_env) + 1
		+ strlen (LSR_FILE_BANNING_USERFILE) + 1);
	if ( user_ban_file_name == NULL )
	{
		fail("test_banned_in_userfile_file: cannot allocate memory: errno=%d\n", errno);
	}
	strcpy (user_ban_file_name, home_env);
	strcat (user_ban_file_name, "/");
	strcat (user_ban_file_name, LSR_FILE_BANNING_USERFILE);

	user_ban_file = fopen (user_ban_file_name, "a+");
	if ( user_ban_file == NULL )
	{
		err = errno;
		free (user_ban_file_name);
		fail("test_banned_in_userfile_file: cannot open user file: errno=%d\n", err);
	}

	lsrtest_set_inside_write (1);
	fseek (user_ban_file, 0, SEEK_END);
	file_len = ftell (user_ban_file);
	fwrite ("\n" LSR_TEST_FILENAME "\n", 1,
		strlen("\n" LSR_TEST_FILENAME "\n"), user_ban_file);
	fclose (user_ban_file);
	lsrtest_set_inside_write (0);
	lsrtest_set_nwritten (0);
	lsrtest_set_nwritten_total (0);

	fd = open(LSR_TEST_FILENAME, O_WRONLY | O_TRUNC);
	nwritten = lsrtest_get_nwritten ();
	err = errno;
	if ( file_len == 0 )
	{
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
	ck_assert_int_eq(nwritten, 0);
}
END_TEST
#endif

#ifdef LSR_CAN_USE_ENV
START_TEST(test_banned_in_env_prog)
{
	int fd;
	FILE * env_ban_file;
	char env_ban_file_name[] = "libsecrm.env";
	int err;
	long file_len;
	int res;
	size_t nwritten;

	lsrtest_set_inside_write (1);
	printf("test_banned_in_env_prog\n");
	lsrtest_set_inside_write (0);
	lsrtest_set_nwritten (0);
	lsrtest_set_nwritten_total (0);

	res = setenv(LSR_PROG_BANNING_ENV, env_ban_file_name, 1);
	if ( res != 0 )
	{
		fail("test_banned_in_env_prog: cannot set environment: errno=%d\n", errno);
	}

	env_ban_file = fopen (env_ban_file_name, "a+");
	if ( env_ban_file == NULL )
	{
		fail("test_banned_in_env_prog: cannot open user file: errno=%d\n", errno);
	}

	lsrtest_set_inside_write (1);
	fseek (env_ban_file, 0, SEEK_END);
	file_len = ftell (env_ban_file);
	fwrite ("\nlsrtest\n", 1, strlen("\nlsrtest\n"), env_ban_file);
	fclose (env_ban_file);
	lsrtest_set_inside_write (0);
	lsrtest_set_nwritten (0);
	lsrtest_set_nwritten_total (0);

	fd = open(LSR_TEST_FILENAME, O_WRONLY | O_TRUNC);
	nwritten = lsrtest_get_nwritten ();
	err = errno;
	if ( file_len == 0 )
	{
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
	ck_assert_int_eq(nwritten, 0);
}
END_TEST

START_TEST(test_banned_in_env_file)
{
	int fd;
	FILE * env_ban_file;
	char env_ban_file_name[] = "libsecrm.env";
	int err;
	long file_len;
	int res;
	size_t nwritten;

	lsrtest_set_inside_write (1);
	printf("test_banned_in_env_file\n");
	lsrtest_set_inside_write (0);
	lsrtest_set_nwritten (0);
	lsrtest_set_nwritten_total (0);

	res = setenv(LSR_FILE_BANNING_ENV, env_ban_file_name, 1);
	if ( res != 0 )
	{
		fail("test_banned_in_env_prog: cannot set environment: errno=%d\n", errno);
	}

	env_ban_file = fopen (env_ban_file_name, "a+");
	if ( env_ban_file == NULL )
	{
		fail("test_banned_in_env_file: cannot open user file: errno=%d\n", errno);
	}

	lsrtest_set_inside_write (1);
	fseek (env_ban_file, 0, SEEK_END);
	file_len = ftell (env_ban_file);
	fwrite ("\n" LSR_TEST_FILENAME "\n", 1,
		strlen("\n" LSR_TEST_FILENAME "\n"), env_ban_file);
	fclose (env_ban_file);
	lsrtest_set_inside_write (0);
	lsrtest_set_nwritten (0);
	lsrtest_set_nwritten_total (0);

	fd = open(LSR_TEST_FILENAME, O_WRONLY | O_TRUNC);
	nwritten = lsrtest_get_nwritten ();
	err = errno;
	if ( file_len == 0 )
	{
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
	ck_assert_int_eq(nwritten, 0);
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
