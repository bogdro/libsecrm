/*
 * A library for secure removing files.
 *	-- unit test for file truncating functions.
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

START_TEST(test_ftruncate)
{
	int fd;
	int r;
	size_t nwritten;

	lsrtest_set_inside_write (1);
	printf("test_ftruncate\n");
	lsrtest_set_inside_write (0);
	lsrtest_set_nwritten (0);
	lsrtest_set_nwritten_total (0);

	fd = open(LSR_TEST_FILENAME, O_RDWR);
	nwritten = lsrtest_get_nwritten ();
	if (fd >= 0)
	{
		r = ftruncate(fd, 0);
		nwritten = lsrtest_get_nwritten ();
		if (r != 0)
		{
			fail("test_ftruncate: file could not have been truncated: errno=%d, r=%d\n", errno, r);
		}
		close(fd);
	}
	else
	{
		fail("test_ftruncate: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq(nwritten, LSR_TEST_FILE_LENGTH);
}
END_TEST

START_TEST(test_ftruncate_banned)
{
	int fd;
	int r;
	size_t nwritten;

	lsrtest_set_inside_write (1);
	printf("test_ftruncate_banned\n");
	lsrtest_set_inside_write (0);
	lsrtest_set_nwritten (0);
	lsrtest_set_nwritten_total (0);

	fd = open(LSR_TEST_BANNED_FILENAME, O_RDWR);
	nwritten = lsrtest_get_nwritten ();
	ck_assert_int_eq(nwritten, 0);
	if (fd >= 0)
	{
		write (fd, "aaa", 3);
		lsrtest_set_nwritten (0);
		r = ftruncate(fd, 0);
		nwritten = lsrtest_get_nwritten ();
		if (r != 0)
		{
			fail("test_ftruncate_banned: file could not have been truncated: errno=%d, r=%d\n", errno, r);
		}
		close(fd);
	}
	else
	{
		fail("test_ftruncate_banned: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq(nwritten, 0);
}
END_TEST

START_TEST(test_truncate)
{
	int r;
	size_t nwritten;

	lsrtest_set_inside_write (1);
	printf("test_truncate\n");
	lsrtest_set_inside_write (0);
	lsrtest_set_nwritten (0);
	lsrtest_set_nwritten_total (0);

	r = truncate(LSR_TEST_FILENAME, 0);
	nwritten = lsrtest_get_nwritten ();
	if (r != 0)
	{
		fail("test_truncate: file could not have been truncated: errno=%d, r=%d\n", errno, r);
	}
	ck_assert_int_eq(nwritten, LSR_TEST_FILE_LENGTH);
}
END_TEST

START_TEST(test_truncate_banned)
{
	int r;
	size_t nwritten;

	lsrtest_set_inside_write (1);
	printf("test_truncate_banned\n");
	lsrtest_prepare_banned_file();
	lsrtest_set_inside_write (0);
	lsrtest_set_nwritten (0);
	lsrtest_set_nwritten_total (0);

	r = truncate(LSR_TEST_BANNED_FILENAME, 0);
	nwritten = lsrtest_get_nwritten ();
	if (r != 0)
	{
		fail("test_truncate_banned: file could not have been truncated: errno=%d, r=%d\n", errno, r);
	}
	ck_assert_int_eq(nwritten, 0);
}
END_TEST


#ifdef HAVE_FALLOCATE
START_TEST(test_fallocate)
{
	int fd;
	int r;
	size_t nwritten;

	lsrtest_set_inside_write (1);
	printf("test_fallocate\n");
	lsrtest_set_inside_write (0);
	lsrtest_set_nwritten (0);
	lsrtest_set_nwritten_total (0);

	fd = open(LSR_TEST_FILENAME, O_RDWR);
	nwritten = lsrtest_get_nwritten ();
	if (fd >= 0)
	{
		ck_assert_int_eq(nwritten, 0);
		lsrtest_set_nwritten (0);
		r = fallocate(fd, 0, 0, LSR_TEST_FILE_EXT_LENGTH);
		nwritten = lsrtest_get_nwritten ();
		close(fd);
		ck_assert_int_eq(nwritten, LSR_TEST_FILE_EXT_LENGTH - LSR_TEST_FILE_LENGTH);
		if (r != 0)
		{
			fail("test_fallocate: file not extended: errno=%d\n", errno);
		}
	}
	else
	{
		fail("test_fallocate: file not opened: errno=%d\n", errno);
	}
}
END_TEST
#endif

#ifdef HAVE_POSIX_FALLOCATE
START_TEST(test_posix_fallocate)
{
	int fd;
	int r;
	size_t nwritten;

	lsrtest_set_inside_write (1);
	printf("test_posix_fallocate\n");
	lsrtest_set_inside_write (0);
	lsrtest_set_nwritten (0);
	lsrtest_set_nwritten_total (0);

	fd = open(LSR_TEST_FILENAME, O_RDWR);
	nwritten = lsrtest_get_nwritten ();
	if (fd >= 0)
	{
		ck_assert_int_eq(nwritten, 0);
		lsrtest_set_nwritten (0);
		r = posix_fallocate(fd, 0, LSR_TEST_FILE_EXT_LENGTH);
		nwritten = lsrtest_get_nwritten ();
		close(fd);
		ck_assert_int_eq(nwritten, LSR_TEST_FILE_EXT_LENGTH - LSR_TEST_FILE_LENGTH);
		if (r != 0)
		{
			fail("test_posix_fallocate: file not extended: errno=%d\n", errno);
		}
	}
	else
	{
		fail("test_posix_fallocate: file not opened: errno=%d\n", errno);
	}
}
END_TEST
#endif

/* ======================================================= */

static Suite * lsr_create_suite(void)
{
	Suite * s = suite_create("libsecrm_trunc");

	TCase * tests_falloc_trunc = tcase_create("falloc_trunc");

#ifdef HAVE_FALLOCATE
	tcase_add_test(tests_falloc_trunc, test_fallocate);
#endif
#ifdef HAVE_POSIX_FALLOCATE
	tcase_add_test(tests_falloc_trunc, test_posix_fallocate);
#endif
	tcase_add_test(tests_falloc_trunc, test_ftruncate);
	tcase_add_test(tests_falloc_trunc, test_truncate);
	tcase_add_test(tests_falloc_trunc, test_truncate_banned);

	lsrtest_add_fixtures (tests_falloc_trunc);

	/* set 30-second timeouts */
	tcase_set_timeout(tests_falloc_trunc, 30);

	suite_add_tcase(s, tests_falloc_trunc);

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
