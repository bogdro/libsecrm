/*
 * LibSecRm - A library for secure removing files.
 *	-- unit test for file truncating functions.
 *
 * Copyright (C) 2015-2024 Bogdan Drozdowski, bogdro (at) users . sourceforge . net
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

#include "lsrtest_common.h"

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

/* ======================================================= */

START_TEST(test_ftruncate)
{
	int fd;
	int r;
	size_t nwritten;

	LSR_PROLOG_FOR_TEST();

	fd = open(LSR_TEST_FILENAME, O_RDWR);
	nwritten = lsrtest_get_nwritten ();
	if (fd >= 0)
	{
		r = ftruncate(fd, 0);
		nwritten = lsrtest_get_nwritten ();
		if (r != 0)
		{
			ck_abort_msg("test_ftruncate: file could not have been truncated: errno=%d, r=%d\n", errno, r);
		}
		close(fd);
	}
	else
	{
		ck_abort_msg("test_ftruncate: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq((int) nwritten, LSR_TEST_FILE_LENGTH);
}
END_TEST

START_TEST(test_ftruncate_banned)
{
	int fd;
	int r;
	size_t nwritten;

	lsrtest_prepare_banned_file ();
	LSR_PROLOG_FOR_TEST();

	fd = open(LSR_TEST_BANNED_FILENAME, O_RDWR);
	nwritten = lsrtest_get_nwritten ();
	ck_assert_int_eq((int) nwritten, 0);
	if (fd >= 0)
	{
		write (fd, "aaa", 3);
		lsrtest_set_nwritten (0);
		r = ftruncate(fd, 0);
		nwritten = lsrtest_get_nwritten ();
		if (r != 0)
		{
			ck_abort_msg("test_ftruncate_banned: file could not have been truncated: errno=%d, r=%d\n", errno, r);
		}
		close(fd);
	}
	else
	{
		ck_abort_msg("test_ftruncate_banned: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq((int) nwritten, 0);
}
END_TEST

#ifdef LSR_CAN_USE_PIPE
START_TEST(test_ftruncate_pipe)
{
	int fd;
	int r;
	size_t nwritten;

	lsrtest_prepare_pipe ();
	LSR_PROLOG_FOR_TEST();

	fd = open(LSR_PIPE_FILENAME, O_RDWR);
	nwritten = lsrtest_get_nwritten ();
	ck_assert_int_eq((int) nwritten, 0);
	if (fd >= 0)
	{
		write (fd, "aaa", 3);
		lsrtest_set_nwritten (0);
		r = ftruncate(fd, 0);
		nwritten = lsrtest_get_nwritten ();
		if (r != 0)
		{
			ck_abort_msg("test_ftruncate_pipe: pipe could not have been truncated: errno=%d, r=%d\n", errno, r);
		}
		close(fd);
	}
	else
	{
		ck_abort_msg("test_ftruncate_pipe: pipe not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq((int) nwritten, 0);
}
END_TEST
#endif /* LSR_CAN_USE_PIPE */

/* ======================================================= */

START_TEST(test_ftruncate64)
{
	int fd;
	int r;
	size_t nwritten;

	LSR_PROLOG_FOR_TEST();

	fd = open(LSR_TEST_FILENAME, O_RDWR);
	nwritten = lsrtest_get_nwritten ();
	if (fd >= 0)
	{
		r = ftruncate64(fd, 0);
		nwritten = lsrtest_get_nwritten ();
		if (r != 0)
		{
			ck_abort_msg("test_ftruncate64: file could not have been truncated: errno=%d, r=%d\n", errno, r);
		}
		close(fd);
	}
	else
	{
		ck_abort_msg("test_ftruncate64: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq((int) nwritten, LSR_TEST_FILE_LENGTH);
}
END_TEST

START_TEST(test_ftruncate64_banned)
{
	int fd;
	int r;
	size_t nwritten;

	lsrtest_prepare_banned_file ();
	LSR_PROLOG_FOR_TEST();

	fd = open(LSR_TEST_BANNED_FILENAME, O_RDWR);
	nwritten = lsrtest_get_nwritten ();
	ck_assert_int_eq((int) nwritten, 0);
	if (fd >= 0)
	{
		write (fd, "aaa", 3);
		lsrtest_set_nwritten (0);
		r = ftruncate64(fd, 0);
		nwritten = lsrtest_get_nwritten ();
		if (r != 0)
		{
			ck_abort_msg("test_ftruncate64_banned: file could not have been truncated: errno=%d, r=%d\n", errno, r);
		}
		close(fd);
	}
	else
	{
		ck_abort_msg("test_ftruncate64_banned: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq((int) nwritten, 0);
}
END_TEST

#ifdef LSR_CAN_USE_PIPE
START_TEST(test_ftruncate64_pipe)
{
	int fd;
	int r;
	size_t nwritten;

	lsrtest_prepare_pipe ();
	LSR_PROLOG_FOR_TEST();

	fd = open(LSR_PIPE_FILENAME, O_RDWR);
	nwritten = lsrtest_get_nwritten ();
	ck_assert_int_eq((int) nwritten, 0);
	if (fd >= 0)
	{
		write (fd, "aaa", 3);
		lsrtest_set_nwritten (0);
		r = ftruncate64(fd, 0);
		nwritten = lsrtest_get_nwritten ();
		if (r != 0)
		{
			ck_abort_msg("test_ftruncate64_pipe: pipe could not have been truncated: errno=%d, r=%d\n", errno, r);
		}
		close(fd);
	}
	else
	{
		ck_abort_msg("test_ftruncate64_pipe: pipe not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq((int) nwritten, 0);
}
END_TEST
#endif /* LSR_CAN_USE_PIPE */

/* ======================================================= */

START_TEST(test_truncate)
{
	int r;
	size_t nwritten;

	LSR_PROLOG_FOR_TEST();

	r = truncate(LSR_TEST_FILENAME, 0);
	nwritten = lsrtest_get_nwritten ();
	if (r != 0)
	{
		ck_abort_msg("test_truncate: file could not have been truncated: errno=%d, r=%d\n", errno, r);
	}
	ck_assert_int_eq((int) nwritten, LSR_TEST_FILE_LENGTH);
}
END_TEST

START_TEST(test_truncate_banned)
{
	int r;
	size_t nwritten;

	lsrtest_prepare_banned_file();
	LSR_PROLOG_FOR_TEST();

	r = truncate(LSR_TEST_BANNED_FILENAME, 0);
	nwritten = lsrtest_get_nwritten ();
	if (r != 0)
	{
		ck_abort_msg("test_truncate_banned: file could not have been truncated: errno=%d, r=%d\n", errno, r);
	}
	ck_assert_int_eq((int) nwritten, 0);
}
END_TEST

#ifdef LSR_CAN_USE_PIPE
START_TEST(test_truncate_pipe)
{
	int r;
	size_t nwritten;

	lsrtest_prepare_pipe ();
	LSR_PROLOG_FOR_TEST();

	r = truncate(LSR_PIPE_FILENAME, 0);
	nwritten = lsrtest_get_nwritten ();
	if (r != 0)
	{
		ck_abort_msg("test_truncate_pipe: pipe could not have been truncated: errno=%d, r=%d\n", errno, r);
	}
	ck_assert_int_eq((int) nwritten, 0);
}
END_TEST
#endif /* LSR_CAN_USE_PIPE */

/* ======================================================= */

#ifdef HAVE_FALLOCATE
START_TEST(test_fallocate)
{
	int fd;
	int r;
	size_t nwritten;

	LSR_PROLOG_FOR_TEST();

	fd = open(LSR_TEST_FILENAME, O_RDWR);
	nwritten = lsrtest_get_nwritten ();
	if (fd >= 0)
	{
		ck_assert_int_eq((int) nwritten, 0);
		lsrtest_set_nwritten (0);
		r = fallocate(fd, 0, 0, LSR_TEST_FILE_EXT_LENGTH);
		nwritten = lsrtest_get_nwritten ();
		close(fd);
		ck_assert_int_eq((int) nwritten, LSR_TEST_FILE_EXT_LENGTH - LSR_TEST_FILE_LENGTH);
		if (r != 0)
		{
			ck_abort_msg("test_fallocate: file not extended: errno=%d\n", errno);
		}
	}
	else
	{
		ck_abort_msg("test_fallocate: file not opened: errno=%d\n", errno);
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

	LSR_PROLOG_FOR_TEST();

	fd = open(LSR_TEST_FILENAME, O_RDWR);
	nwritten = lsrtest_get_nwritten ();
	if (fd >= 0)
	{
		ck_assert_int_eq((int) nwritten, 0);
		lsrtest_set_nwritten (0);
		r = posix_fallocate(fd, 0, LSR_TEST_FILE_EXT_LENGTH);
		nwritten = lsrtest_get_nwritten ();
		close(fd);
		ck_assert_int_eq((int) nwritten, LSR_TEST_FILE_EXT_LENGTH - LSR_TEST_FILE_LENGTH);
		if (r != 0)
		{
			ck_abort_msg("test_posix_fallocate: file not extended: errno=%d\n", errno);
		}
	}
	else
	{
		ck_abort_msg("test_posix_fallocate: file not opened: errno=%d\n", errno);
	}
}
END_TEST
#endif

#ifdef HAVE_POSIX_FALLOCATE64
START_TEST(test_posix_fallocate64)
{
	int fd;
	int r;
	size_t nwritten;

	LSR_PROLOG_FOR_TEST();

	fd = open(LSR_TEST_FILENAME, O_RDWR);
	nwritten = lsrtest_get_nwritten ();
	if (fd >= 0)
	{
		ck_assert_int_eq((int) nwritten, 0);
		lsrtest_set_nwritten (0);
		r = posix_fallocate64(fd, 0, LSR_TEST_FILE_EXT_LENGTH);
		nwritten = lsrtest_get_nwritten ();
		close(fd);
		ck_assert_int_eq((int) nwritten, LSR_TEST_FILE_EXT_LENGTH - LSR_TEST_FILE_LENGTH);
		if (r != 0)
		{
			ck_abort_msg("test_posix_fallocate64: file not extended: errno=%d\n", errno);
		}
	}
	else
	{
		ck_abort_msg("test_posix_fallocate64: file not opened: errno=%d\n", errno);
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
#ifdef HAVE_POSIX_FALLOCATE64
	tcase_add_test(tests_falloc_trunc, test_posix_fallocate64);
#endif

	tcase_add_test(tests_falloc_trunc, test_ftruncate);
	tcase_add_test(tests_falloc_trunc, test_ftruncate_banned);
#ifdef LSR_CAN_USE_PIPE
	tcase_add_test(tests_falloc_trunc, test_ftruncate_pipe);
#endif

	tcase_add_test(tests_falloc_trunc, test_ftruncate64);
	tcase_add_test(tests_falloc_trunc, test_ftruncate64_banned);
#ifdef LSR_CAN_USE_PIPE
	tcase_add_test(tests_falloc_trunc, test_ftruncate64_pipe);
#endif

	tcase_add_test(tests_falloc_trunc, test_truncate);
	tcase_add_test(tests_falloc_trunc, test_truncate_banned);
#ifdef LSR_CAN_USE_PIPE
	tcase_add_test(tests_falloc_trunc, test_truncate_pipe);
#endif

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
