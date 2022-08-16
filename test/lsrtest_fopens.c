/*
 * A library for secure removing files.
 *	-- unit test for file opening functions.
 *
 * Copyright (C) 2015-2019 Bogdan Drozdowski, bogdandr (at) op.pl
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

START_TEST(test_fopen_r)
{
	FILE * f;
	size_t nwritten;

	lsrtest_set_inside_write (1);
	printf("test_fopen_r\n");
	lsrtest_set_inside_write (0);
	lsrtest_set_nwritten (0);
	lsrtest_set_nwritten_total (0);

	f = fopen(LSR_TEST_FILENAME, "r");
	nwritten = lsrtest_get_nwritten ();
	if (f != NULL)
	{
		fclose(f);
	}
	else
	{
		fail("test_fopen_r: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq(nwritten, 0);
}
END_TEST

START_TEST(test_fopen_w)
{
	FILE * f;
	size_t nwritten;

	lsrtest_set_inside_write (1);
	printf("test_fopen_w\n");
	lsrtest_set_inside_write (0);
	lsrtest_set_nwritten (0);
	lsrtest_set_nwritten_total (0);

	f = fopen(LSR_TEST_FILENAME, "w");
	nwritten = lsrtest_get_nwritten ();
	if (f != NULL)
	{
		fclose(f);
	}
	else
	{
		fail("test_fopen_w: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq(nwritten, LSR_TEST_FILE_LENGTH);
}
END_TEST

START_TEST(test_fopen_w_banned)
{
	FILE * f;
	size_t nwritten;

	lsrtest_set_inside_write (1);
	printf("test_fopen_w_banned\n");
	lsrtest_prepare_banned_file();
	lsrtest_set_inside_write (0);
	lsrtest_set_nwritten (0);
	lsrtest_set_nwritten_total (0);

	f = fopen(LSR_TEST_BANNED_FILENAME, "w");
	nwritten = lsrtest_get_nwritten ();
	if (f != NULL)
	{
		fclose(f);
	}
	else
	{
		fail("test_fopen_w_banned: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq(nwritten, 0);
}
END_TEST

START_TEST(test_freopen_rr)
{
	FILE * f;
	size_t nwritten;

	lsrtest_set_inside_write (1);
	printf("test_freopen_rr\n");
	lsrtest_set_inside_write (0);
	lsrtest_set_nwritten (0);
	lsrtest_set_nwritten_total (0);

	f = fopen(LSR_TEST_FILENAME, "r");
	nwritten = lsrtest_get_nwritten ();
	if (f != NULL)
	{
		ck_assert_int_eq(nwritten, 0);
		lsrtest_set_inside_write (0);
		lsrtest_set_nwritten (0);
		lsrtest_set_nwritten_total (0);

		f = freopen(LSR_TEST_FILENAME, "r", f);
		nwritten = lsrtest_get_nwritten ();
		if (f != NULL)
		{
			fclose(f);
		}
		else
		{
			fail("test_freopen_rr: file not re-opened: errno=%d\n", errno);
		}
	}
	else
	{
		fail("test_freopen_rr: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq(nwritten, 0);
}
END_TEST

START_TEST(test_freopen_rw)
{
	FILE * f;
	size_t nwritten;

	lsrtest_set_inside_write (1);
	printf("test_freopen_rw\n");
	lsrtest_set_inside_write (0);
	lsrtest_set_nwritten (0);
	lsrtest_set_nwritten_total (0);

	f = fopen(LSR_TEST_FILENAME, "r");
	nwritten = lsrtest_get_nwritten ();
	if (f != NULL)
	{
		ck_assert_int_eq(nwritten, 0);
		lsrtest_set_inside_write (0);
		lsrtest_set_nwritten (0);
		lsrtest_set_nwritten_total (0);

		f = freopen(LSR_TEST_FILENAME, "w", f);
		nwritten = lsrtest_get_nwritten ();
		if (f != NULL)
		{
			fclose(f);
		}
		else
		{
			fail("test_freopen_rw: file not re-opened: errno=%d\n", errno);
		}
	}
	else
	{
		fail("test_freopen_rw: file not opened: errno=%d\n", errno);
	}
	/* file already opened and re-opened won't be wiped - fcntl()
	won't allow setting the exclusive lock */
	ck_assert_int_eq(nwritten, 0);
}
END_TEST

START_TEST(test_freopen_rw_banned)
{
	FILE * f;
	size_t nwritten;

	lsrtest_set_inside_write (1);
	printf("test_freopen_rw_banned\n");
	lsrtest_prepare_banned_file();
	lsrtest_set_inside_write (0);
	lsrtest_set_nwritten (0);
	lsrtest_set_nwritten_total (0);

	f = fopen(LSR_TEST_FILENAME, "r");
	nwritten = lsrtest_get_nwritten ();
	if (f != NULL)
	{
		ck_assert_int_eq(nwritten, 0);
		lsrtest_set_inside_write (0);
		lsrtest_set_nwritten (0);
		lsrtest_set_nwritten_total (0);

		f = freopen(LSR_TEST_BANNED_FILENAME, "w", f);
		nwritten = lsrtest_get_nwritten ();
		if (f != NULL)
		{
			fclose(f);
		}
		else
		{
			fail("test_freopen_rw_banned: file not re-opened: errno=%d\n", errno);
		}
	}
	else
	{
		fail("test_freopen_rw_banned: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq(nwritten, 0);
}
END_TEST


START_TEST(test_freopen_rw_stdout)
{
	FILE * f;
	size_t nwritten;

	lsrtest_set_inside_write (1);
	printf("test_freopen_rw_stdout\n");
	lsrtest_set_inside_write (0);
	lsrtest_set_nwritten (0);
	lsrtest_set_nwritten_total (0);

	f = freopen(LSR_TEST_FILENAME, "w", stdout);
	nwritten = lsrtest_get_nwritten ();
	if (f != NULL)
	{
		fclose(f);
	}
	else
	{
		fail("test_freopen_rw_stdout: file not re-opened: errno=%d\n", errno);
	}
	ck_assert_int_eq(nwritten, LSR_TEST_FILE_LENGTH);
}
END_TEST

START_TEST(test_freopen_rw_stdout_banned)
{
	FILE * f;
	size_t nwritten;

	lsrtest_set_inside_write (1);
	printf("test_freopen_rw_stdout_banned\n");
	lsrtest_prepare_banned_file();
	lsrtest_set_inside_write (0);
	lsrtest_set_nwritten (0);
	lsrtest_set_nwritten_total (0);

	f = freopen(LSR_TEST_BANNED_FILENAME, "w", stdout);
	nwritten = lsrtest_get_nwritten ();
	if (f != NULL)
	{
		fclose(f);
	}
	else
	{
		fail("test_freopen_rw_stdout_banned: file not re-opened: errno=%d\n", errno);
	}
	ck_assert_int_eq(nwritten, 0);
}
END_TEST

START_TEST(test_freopen_wr)
{
	FILE * f;
	size_t nwritten;

	lsrtest_set_inside_write (1);
	printf("test_freopen_wr\n");
	lsrtest_set_inside_write (0);
	lsrtest_set_nwritten (0);
	lsrtest_set_nwritten_total (0);

	f = fopen(LSR_TEST_FILENAME, "w");
	nwritten = lsrtest_get_nwritten ();
	if (f != NULL)
	{
		ck_assert_int_eq(nwritten, LSR_TEST_FILE_LENGTH);
		lsrtest_set_inside_write (0);
		lsrtest_set_nwritten (0);
		lsrtest_set_nwritten_total (0);

		f = freopen(LSR_TEST_FILENAME, "r", f);
		nwritten = lsrtest_get_nwritten ();
		if (f != NULL)
		{
			fclose(f);
		}
		else
		{
			fail("test_freopen_wr: file not re-opened: errno=%d\n", errno);
		}
	}
	else
	{
		fail("test_freopen_wr: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq(lsrtest_get_nwritten (), 0);
}
END_TEST

START_TEST(test_freopen_ww)
{
	FILE * f;
	size_t nwritten;

	lsrtest_set_inside_write (1);
	printf("test_freopen_ww\n");
	lsrtest_set_inside_write (0);
	lsrtest_set_nwritten (0);
	lsrtest_set_nwritten_total (0);

	f = fopen(LSR_TEST_FILENAME, "w");
	nwritten = lsrtest_get_nwritten ();
	if (f != NULL)
	{
		ck_assert_int_eq(nwritten, LSR_TEST_FILE_LENGTH);
		lsrtest_set_inside_write (0);
		lsrtest_set_nwritten (0);
		lsrtest_set_nwritten_total (0);

		f = freopen(LSR_TEST_FILENAME, "w", f);
		nwritten = lsrtest_get_nwritten ();
		if (f != NULL)
		{
			fclose(f);
		}
		else
		{
			fail("test_freopen_ww: file not re-opened: errno=%d\n", errno);
		}
	}
	else
	{
		fail("test_freopen_ww: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq(nwritten, 0);
}
END_TEST

START_TEST(test_freopen_ww_banned1)
{
	FILE * f;
	size_t nwritten;

	lsrtest_set_inside_write (1);
	printf("test_freopen_ww_banned1\n");
	lsrtest_prepare_banned_file();
	lsrtest_set_inside_write (0);
	lsrtest_set_nwritten (0);
	lsrtest_set_nwritten_total (0);

	f = fopen(LSR_TEST_BANNED_FILENAME, "w");
	nwritten = lsrtest_get_nwritten ();
	if (f != NULL)
	{
		ck_assert_int_eq(nwritten, 0);
		lsrtest_set_inside_write (0);
		lsrtest_set_nwritten (0);
		lsrtest_set_nwritten_total (0);

		f = freopen(LSR_TEST_FILENAME, "w", f);
		nwritten = lsrtest_get_nwritten ();
		if (f != NULL)
		{
			fclose(f);
		}
		else
		{
			fail("test_freopen_ww_banned1: file not re-opened: errno=%d\n", errno);
		}
	}
	else
	{
		fail("test_freopen_ww_banned1: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq(nwritten, LSR_TEST_FILE_LENGTH);
}
END_TEST

START_TEST(test_freopen_ww_banned2)
{
	FILE * f;
	size_t nwritten;

	lsrtest_set_inside_write (1);
	printf("test_freopen_ww_banned2\n");
	lsrtest_prepare_banned_file();
	lsrtest_set_inside_write (0);
	lsrtest_set_nwritten (0);
	lsrtest_set_nwritten_total (0);

	f = fopen(LSR_TEST_FILENAME, "w");
	nwritten = lsrtest_get_nwritten ();
	if (f != NULL)
	{
		ck_assert_int_eq(nwritten, LSR_TEST_FILE_LENGTH);
		lsrtest_set_inside_write (0);
		lsrtest_set_nwritten (0);
		lsrtest_set_nwritten_total (0);

		f = freopen(LSR_TEST_BANNED_FILENAME, "w", f);
		nwritten = lsrtest_get_nwritten ();
		if (f != NULL)
		{
			fclose(f);
		}
		else
		{
			fail("test_freopen_ww_banned2: file not re-opened: errno=%d\n", errno);
		}
	}
	else
	{
		fail("test_freopen_ww_banned2: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq(nwritten, 0);
}
END_TEST

START_TEST(test_fdopen_r)
{
	int fd;
	FILE * f;
	size_t nwritten;

	lsrtest_set_inside_write (1);
	printf("test_fdopen_r\n");
	lsrtest_set_inside_write (0);
	lsrtest_set_nwritten (0);
	lsrtest_set_nwritten_total (0);

	fd = open(LSR_TEST_FILENAME, O_RDONLY);
	nwritten = lsrtest_get_nwritten ();
	if (fd >= 0)
	{
		ck_assert_int_eq(nwritten, 0);
		lsrtest_set_inside_write (0);
		lsrtest_set_nwritten (0);
		lsrtest_set_nwritten_total (0);

		f = fdopen(fd, "r");
		nwritten = lsrtest_get_nwritten ();
		if (f != NULL)
		{
			fclose(f);
		}
		else
		{
			fail("test_fdopen_r: file not re-opened: errno=%d\n", errno);
		}
	}
	else
	{
		fail("test_fdopen_r: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq(nwritten, 0);
}
END_TEST

START_TEST(test_fdopen_w)
{
	int fd;
	FILE * f;
	size_t nwritten;

	lsrtest_set_inside_write (1);
	printf("test_fdopen_w\n");
	lsrtest_set_inside_write (0);
	lsrtest_set_nwritten (0);
	lsrtest_set_nwritten_total (0);

	fd = open(LSR_TEST_FILENAME, O_RDWR);
	nwritten = lsrtest_get_nwritten ();
	if (fd >= 0)
	{
		ck_assert_int_eq(nwritten, 0);
		lsrtest_set_inside_write (0);
		lsrtest_set_nwritten (0);
		lsrtest_set_nwritten_total (0);

		f = fdopen(fd, "w");
		nwritten = lsrtest_get_nwritten ();
		if (f != NULL)
		{
			fclose(f);
		}
		else
		{
			fail("test_fdopen_w: file not re-opened: errno=%d\n", errno);
		}
	}
	else
	{
		fail("test_fdopen_w: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq(nwritten, 0); /* fdopen(w) should not truncate */
}
END_TEST


/* ======================================================= */

static Suite * lsr_create_suite(void)
{
	Suite * s = suite_create("libsecrm_open");

	TCase * tests_fopen = tcase_create("fopen");

	tcase_add_test(tests_fopen, test_fopen_r);
	tcase_add_test(tests_fopen, test_fopen_w);
	tcase_add_test(tests_fopen, test_freopen_rr);
	tcase_add_test(tests_fopen, test_freopen_rw);
	tcase_add_test(tests_fopen, test_freopen_wr);
	tcase_add_test(tests_fopen, test_freopen_ww);
	tcase_add_test(tests_fopen, test_fdopen_r);
	tcase_add_test(tests_fopen, test_fdopen_w);

	tcase_add_test(tests_fopen, test_freopen_rw_banned);
	tcase_add_test(tests_fopen, test_freopen_ww_banned1);
	tcase_add_test(tests_fopen, test_freopen_ww_banned2);
	tcase_add_test(tests_fopen, test_freopen_rw_stdout_banned);
	tcase_add_test(tests_fopen, test_freopen_rw_stdout);
	tcase_add_test(tests_fopen, test_fopen_w_banned);

	lsrtest_add_fixtures (tests_fopen);

	/* set 30-second timeouts */
	tcase_set_timeout(tests_fopen, 30);

	suite_add_tcase(s, tests_fopen);

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
