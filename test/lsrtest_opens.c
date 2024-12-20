/*
 * LibSecRm - A library for secure removing files.
 *	-- unit test for file opening functions.
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
		ck_abort_msg("test_openat_rdonly: file not opened: errno=%d\n", errno);
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
		ck_abort_msg("test_openat_rdwr: file not opened: errno=%d\n", errno);
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
		ck_abort_msg("test_openat_wronly: file not opened: errno=%d\n", errno);
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
		ck_abort_msg("test_openat_trunc: file not opened: errno=%d\n", errno);
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
		ck_abort_msg("test_openat_trunc_banned: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq((int) nwritten, 0);
}
END_TEST

#ifdef HAVE_SYMLINK
START_TEST(test_openat_trunc_link)
{
	int r;
	size_t nwritten;
	int fd;


	LSR_PROLOG_FOR_TEST();

	r = symlink (LSR_TEST_FILENAME, LSR_LINK_FILENAME);
	if (r != 0)
	{
		ck_abort_msg("test_openat_trunc_link: link could not have been created: errno=%d, r=%d\n", errno, r);
	}
	fd = openat(AT_FDCWD, LSR_LINK_FILENAME, O_WRONLY | O_TRUNC);
	nwritten = lsrtest_get_nwritten ();
	if (fd >= 0)
	{
		close(fd);
	}
	else
	{
		ck_abort_msg("test_openat_trunc_link: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq((int) nwritten, LSR_TEST_FILE_LENGTH);
}
END_TEST
#endif /* HAVE_SYMLINK */

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
		ck_abort_msg("test_openat_pipe_trunc: file not opened: errno=%d\n", errno);
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
		ck_abort_msg("test_open_rdwr: file not opened: errno=%d\n", errno);
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
		ck_abort_msg("test_open_wronly: file not opened: errno=%d\n", errno);
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
		ck_abort_msg("test_open_rdonly: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq((int) nwritten, 0);
}
END_TEST

START_TEST(test_open_proc)
{
	int fd;
	size_t nwritten;
	/* strlen(/proc/) + strlen(maxuint or "self") + strlen(/exe) + '\0' */
	char procpath[6 + 11 + 4 + 1];

	LSR_PROLOG_FOR_TEST();

#ifdef HAVE_SNPRINTF
# ifdef HAVE_GETPID
	snprintf (procpath, sizeof(procpath) - 1, "/proc/%d/exe", getpid());
# else
	strncpy (procpath, "/proc/self/exe", sizeof(procpath) - 1);
# endif
#else
# ifdef HAVE_GETPID
	sprintf (procpath, "/proc/%d/exe", getpid());
# else
	strncpy (procpath, "/proc/self/exe", sizeof(procpath) - 1);
# endif
#endif
	fd = open(procpath, O_RDONLY);
	nwritten = lsrtest_get_nwritten ();
	if (fd >= 0)
	{
		close(fd);
	}
	else
	{
		ck_abort_msg("test_open_proc: file not opened: errno=%d\n", errno);
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
		ck_abort_msg("test_open_dev: file not opened: errno=%d\n", errno);
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
		ck_abort_msg("test_open_trunc: file not opened: errno=%d\n", errno);
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
		ck_abort_msg("test_open_trunc_banned: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq((int) nwritten, 0);
}
END_TEST

#ifdef HAVE_SYMLINK
START_TEST(test_open_trunc_link)
{
	int r;
	size_t nwritten;
	int fd;


	LSR_PROLOG_FOR_TEST();

	r = symlink (LSR_TEST_FILENAME, LSR_LINK_FILENAME);
	if (r != 0)
	{
		ck_abort_msg("test_open_trunc_link: link could not have been created: errno=%d, r=%d\n", errno, r);
	}
	fd = open(LSR_LINK_FILENAME, O_WRONLY | O_TRUNC);
	nwritten = lsrtest_get_nwritten ();
	if (fd >= 0)
	{
		close(fd);
	}
	else
	{
		ck_abort_msg("test_open_trunc_link: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq((int) nwritten, LSR_TEST_FILE_LENGTH);
}
END_TEST
#endif /* HAVE_SYMLINK */

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
		ck_abort_msg("test_open_trunc_pipe: file not opened: errno=%d\n", errno);
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
		ck_abort_msg("test_wipe_opened: file not opened: errno=%d\n", errno);
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
		ck_abort_msg("test_wipe_opened: file not opened: errno=%d\n", errno);
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
# ifdef HAVE_SYMLINK
	tcase_add_test(tests_open, test_openat_trunc_link);
# endif
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
#ifdef HAVE_SYMLINK
	tcase_add_test(tests_open, test_open_trunc_link);
#endif
#ifdef LSR_CAN_USE_PIPE
	tcase_add_test(tests_open, test_open_trunc_pipe);
#endif

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
