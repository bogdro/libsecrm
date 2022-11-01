/*
 * A library for secure removing files.
 *	-- unit test for file opening functions.
 *
 * Copyright (C) 2015-2022 Bogdan Drozdowski, bogdro (at) users . sourceforge . net
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

#ifdef HAVE_OPENAT
START_TEST(test_openat_rdonly)
{
	int fd;
	size_t nwritten;

	LSR_PROLOG_FOR_TEST();

	fd = openat(AT_FDCWD, LSR_TEST_FILENAME, O_RDONLY);
	nwritten = lsrtest_get_nwritten ();
	if (fd >= 0)
	{
		close(fd);
	}
	else
	{
		fail("test_openat_rdonly: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq((int) nwritten, 0);
}
END_TEST

START_TEST(test_openat_rdwr)
{
	int fd;
	size_t nwritten;

	LSR_PROLOG_FOR_TEST();

	fd = openat(AT_FDCWD, LSR_TEST_FILENAME, O_RDWR);
	nwritten = lsrtest_get_nwritten ();
	if (fd >= 0)
	{
		close(fd);
	}
	else
	{
		fail("test_openat_rdwr: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq((int) nwritten, 0);
}
END_TEST

START_TEST(test_openat_wronly)
{
	int fd;
	size_t nwritten;

	LSR_PROLOG_FOR_TEST();

	fd = openat(AT_FDCWD, LSR_TEST_FILENAME, O_WRONLY);
	nwritten = lsrtest_get_nwritten ();
	if (fd >= 0)
	{
		close(fd);
	}
	else
	{
		fail("test_openat_wronly: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq((int) nwritten, 0);
}
END_TEST

START_TEST(test_openat_trunc)
{
	int fd;
	size_t nwritten;

	LSR_PROLOG_FOR_TEST();

	fd = openat(AT_FDCWD, LSR_TEST_FILENAME, O_WRONLY | O_TRUNC);
	nwritten = lsrtest_get_nwritten ();
	if (fd >= 0)
	{
		close(fd);
	}
	else
	{
		fail("test_openat_trunc: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq((int) nwritten, LSR_TEST_FILE_LENGTH);
}
END_TEST

START_TEST(test_openat_trunc_banned)
{
	int fd;
	size_t nwritten;

	lsrtest_prepare_banned_file();
	LSR_PROLOG_FOR_TEST();

	fd = openat(AT_FDCWD, LSR_TEST_BANNED_FILENAME, O_WRONLY | O_TRUNC);
	nwritten = lsrtest_get_nwritten ();
	if (fd >= 0)
	{
		close(fd);
	}
	else
	{
		fail("test_openat_trunc_banned: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq((int) nwritten, 0);
}
END_TEST

# ifdef LSR_CAN_USE_PIPE
START_TEST(test_openat_pipe_trunc)
{
	int fd;
	size_t nwritten;

	lsrtest_prepare_pipe ();
	LSR_PROLOG_FOR_TEST();

	fd = openat(AT_FDCWD, LSR_PIPE_FILENAME, O_WRONLY | O_TRUNC);
	nwritten = lsrtest_get_nwritten ();
	if (fd >= 0)
	{
		close(fd);
	}
	else
	{
		fail("test_openat_pipe_trunc: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq((int) nwritten, 0);
}
END_TEST
# endif /* LSR_CAN_USE_PIPE */

#endif /* HAVE_OPENAT */

START_TEST(test_open_rdwr)
{
	int fd;
	size_t nwritten;

	LSR_PROLOG_FOR_TEST();

	fd = open(LSR_TEST_FILENAME, O_RDWR);
	nwritten = lsrtest_get_nwritten ();
	if (fd >= 0)
	{
		close(fd);
	}
	else
	{
		fail("test_open_rdwr: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq((int) nwritten, 0);
}
END_TEST

START_TEST(test_open_wronly)
{
	int fd;
	size_t nwritten;

	LSR_PROLOG_FOR_TEST();

	fd = open(LSR_TEST_FILENAME, O_WRONLY);
	nwritten = lsrtest_get_nwritten ();
	if (fd >= 0)
	{
		close(fd);
	}
	else
	{
		fail("test_open_wronly: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq((int) nwritten, 0);
}
END_TEST

START_TEST(test_open_rdonly)
{
	int fd;
	size_t nwritten;

	LSR_PROLOG_FOR_TEST();

	fd = open(LSR_TEST_FILENAME, O_RDONLY);
	nwritten = lsrtest_get_nwritten ();
	if (fd >= 0)
	{
		close(fd);
	}
	else
	{
		fail("test_open_rdonly: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq((int) nwritten, 0);
}
END_TEST

START_TEST(test_open_proc)
{
	int fd;
	size_t nwritten;

	LSR_PROLOG_FOR_TEST();

	fd = open("/proc/cpuinfo", O_RDONLY);
	nwritten = lsrtest_get_nwritten ();
	if (fd >= 0)
	{
		close(fd);
	}
	else
	{
		fail("test_open_proc: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq((int) nwritten, 0);
}
END_TEST

START_TEST(test_open_dev)
{
	int fd;
	size_t nwritten;

	LSR_PROLOG_FOR_TEST();

	fd = open("/dev/null", O_WRONLY | O_TRUNC);
	nwritten = lsrtest_get_nwritten ();
	if (fd >= 0)
	{
		close(fd);
	}
	else
	{
		fail("test_open_dev: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq((int) nwritten, 0);
}
END_TEST

START_TEST(test_open_trunc)
{
	int fd;
	size_t nwritten;

	LSR_PROLOG_FOR_TEST();

	fd = open(LSR_TEST_FILENAME, O_WRONLY | O_TRUNC);
	nwritten = lsrtest_get_nwritten ();
	if (fd >= 0)
	{
		close(fd);
	}
	else
	{
		fail("test_open_trunc: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq((int) nwritten, LSR_TEST_FILE_LENGTH);
}
END_TEST

START_TEST(test_open_trunc_banned)
{
	int fd;
	size_t nwritten;

	lsrtest_prepare_banned_file ();
	LSR_PROLOG_FOR_TEST();

	fd = open(LSR_TEST_BANNED_FILENAME, O_WRONLY | O_TRUNC);
	nwritten = lsrtest_get_nwritten ();
	if (fd >= 0)
	{
		close(fd);
	}
	else
	{
		fail("test_open_trunc_banned: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq((int) nwritten, 0);
}
END_TEST

#ifdef LSR_CAN_USE_PIPE
START_TEST(test_open_trunc_pipe)
{
	int fd;
	size_t nwritten;

	lsrtest_prepare_pipe ();
	LSR_PROLOG_FOR_TEST();

	fd = open(LSR_PIPE_FILENAME, O_WRONLY | O_TRUNC);
	nwritten = lsrtest_get_nwritten ();
	if (fd >= 0)
	{
		close(fd);
	}
	else
	{
		fail("test_open_trunc_pipe: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq((int) nwritten, 0);
}
END_TEST
#endif /* LSR_CAN_USE_PIPE */
/* ======================================================= */

START_TEST(test_wipe_opened)
{
	int fd;
	int fd1;
	size_t nwritten;

	LSR_PROLOG_FOR_TEST();

	fd1 = open(LSR_TEST_FILENAME, O_RDONLY);
	if (fd1 < 0)
	{
		fail("test_wipe_opened: file not opened: errno=%d\n", errno);
	}
	fd = open(LSR_TEST_FILENAME, O_WRONLY | O_TRUNC);
	nwritten = lsrtest_get_nwritten ();
	if (fd >= 0)
	{
		close(fd);
		close(fd1);
	}
	else
	{
		close(fd1);
		fail("test_wipe_opened: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq((int) nwritten, 0);
}
END_TEST

/* ======================================================= */

static Suite * lsr_create_suite(void)
{
	Suite * s = suite_create("libsecrm_open");

	TCase * tests_open = tcase_create("open");

#ifdef HAVE_OPENAT
	tcase_add_test(tests_open, test_openat_rdonly);
	tcase_add_test(tests_open, test_openat_rdwr);
	tcase_add_test(tests_open, test_openat_wronly);
	tcase_add_test(tests_open, test_openat_trunc);
	tcase_add_test(tests_open, test_openat_trunc_banned);
#  ifdef LSR_CAN_USE_PIPE
	tcase_add_test(tests_open, test_openat_pipe_trunc);
#  endif
#endif
	tcase_add_test(tests_open, test_open_rdwr);
	tcase_add_test(tests_open, test_open_wronly);
	tcase_add_test(tests_open, test_open_rdonly);
	tcase_add_test(tests_open, test_open_proc);
	tcase_add_test(tests_open, test_open_dev);
	tcase_add_test(tests_open, test_open_trunc);
# ifdef LSR_CAN_USE_PIPE
	tcase_add_test(tests_open, test_open_trunc_pipe);
# endif

	tcase_add_test(tests_open, test_wipe_opened);
	tcase_add_test(tests_open, test_open_trunc_banned);

	lsrtest_add_fixtures (tests_open);

	/* set 30-second timeouts */
	tcase_set_timeout(tests_open, 30);

	suite_add_tcase(s, tests_open);

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
