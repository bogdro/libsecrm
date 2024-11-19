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

START_TEST(test_fopen_r)
{
	FILE * f;
	size_t nwritten;

	LSR_PROLOG_FOR_TEST ();

	f = fopen (LSR_TEST_FILENAME, "r");
	nwritten = lsrtest_get_nwritten ();
	if (f != NULL)
	{
		fclose(f);
	}
	else
	{
		ck_abort_msg("test_fopen_r: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq ((int) nwritten, 0);
}
END_TEST

START_TEST(test_fopen_r_proc)
{
	FILE * f;
	size_t nwritten;
	/* strlen(/proc/) + strlen(maxuint or "self") + strlen(/exe) + '\0' */
	char procpath[6 + 11 + 4 + 1];

	LSR_PROLOG_FOR_TEST ();

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
	f = fopen (procpath, "r");
	nwritten = lsrtest_get_nwritten ();
	if (f != NULL)
	{
		fclose(f);
	}
	else
	{
		ck_abort_msg("test_fopen_r_proc: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq ((int) nwritten, 0);
}
END_TEST

START_TEST(test_fopen_w)
{
	FILE * f;
	size_t nwritten;

	LSR_PROLOG_FOR_TEST ();

	f = fopen (LSR_TEST_FILENAME, "w");
	nwritten = lsrtest_get_nwritten ();
	if (f != NULL)
	{
		fclose(f);
	}
	else
	{
		ck_abort_msg("test_fopen_w: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq ((int) nwritten, LSR_TEST_FILE_LENGTH);
}
END_TEST

START_TEST(test_fopen_wp)
{
	FILE * f;
	size_t nwritten;

	LSR_PROLOG_FOR_TEST ();

	f = fopen (LSR_TEST_FILENAME, "w+");
	nwritten = lsrtest_get_nwritten ();
	if (f != NULL)
	{
		fclose(f);
	}
	else
	{
		ck_abort_msg("test_fopen_wp: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq ((int) nwritten, LSR_TEST_FILE_LENGTH);
}
END_TEST

START_TEST(test_fopen_w_banned)
{
	FILE * f;
	size_t nwritten;

	lsrtest_prepare_banned_file ();
	LSR_PROLOG_FOR_TEST ();

	f = fopen (LSR_TEST_BANNED_FILENAME, "w");
	nwritten = lsrtest_get_nwritten ();
	if (f != NULL)
	{
		fclose(f);
	}
	else
	{
		ck_abort_msg("test_fopen_w_banned: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq ((int) nwritten, 0);
}
END_TEST

START_TEST(test_fopen_wp_banned)
{
	FILE * f;
	size_t nwritten;

	lsrtest_prepare_banned_file ();
	LSR_PROLOG_FOR_TEST ();

	f = fopen (LSR_TEST_BANNED_FILENAME, "w+");
	nwritten = lsrtest_get_nwritten ();
	if (f != NULL)
	{
		fclose(f);
	}
	else
	{
		ck_abort_msg("test_fopen_wp_banned: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq ((int) nwritten, 0);
}
END_TEST

START_TEST(test_fopen_w_dev)
{
	FILE * f;
	size_t nwritten;

	LSR_PROLOG_FOR_TEST ();

	f = fopen ("/dev/null", "w");
	nwritten = lsrtest_get_nwritten ();
	if (f != NULL)
	{
		fclose(f);
	}
	else
	{
		ck_abort_msg("test_fopen_w_dev: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq ((int) nwritten, 0);
}
END_TEST

START_TEST(test_fopen_wp_dev)
{
	FILE * f;
	size_t nwritten;

	LSR_PROLOG_FOR_TEST ();

	f = fopen ("/dev/null", "w+");
	nwritten = lsrtest_get_nwritten ();
	if (f != NULL)
	{
		fclose(f);
	}
	else
	{
		ck_abort_msg("test_fopen_wp_dev: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq ((int) nwritten, 0);
}
END_TEST

#ifdef HAVE_SYMLINK
START_TEST(test_fopen_w_link)
{
	FILE * f;
	size_t nwritten;
	int r;

	LSR_PROLOG_FOR_TEST ();

	r = symlink (LSR_TEST_FILENAME, LSR_LINK_FILENAME);
	if (r != 0)
	{
		ck_abort_msg("test_fopen_w_link: link could not have been created: errno=%d, r=%d\n", errno, r);
	}
	f = fopen (LSR_LINK_FILENAME, "w");
	nwritten = lsrtest_get_nwritten ();
	if (f != NULL)
	{
		fclose(f);
	}
	else
	{
		ck_abort_msg("test_fopen_w_link: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq ((int) nwritten, LSR_TEST_FILE_LENGTH);
}
END_TEST

START_TEST(test_fopen_wp_link)
{
	FILE * f;
	size_t nwritten;
	int r;

	LSR_PROLOG_FOR_TEST ();

	r = symlink (LSR_TEST_FILENAME, LSR_LINK_FILENAME);
	if (r != 0)
	{
		ck_abort_msg("test_fopen_wp_link: link could not have been created: errno=%d, r=%d\n", errno, r);
	}
	f = fopen (LSR_LINK_FILENAME, "w+");
	nwritten = lsrtest_get_nwritten ();
	if (f != NULL)
	{
		fclose(f);
	}
	else
	{
		ck_abort_msg("test_fopen_wp_link: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq ((int) nwritten, LSR_TEST_FILE_LENGTH);
}
END_TEST
#endif /* HAVE_SYMLINK */

#ifdef LSR_CAN_USE_PIPE
START_TEST(test_fopen_w_pipe)
{
	FILE * f;
	size_t nwritten;

	lsrtest_prepare_pipe ();
	LSR_PROLOG_FOR_TEST ();

	f = fopen (LSR_PIPE_FILENAME, "w");
	nwritten = lsrtest_get_nwritten ();
	if (f != NULL)
	{
		fclose(f);
	}
	else
	{
		ck_abort_msg("test_fopen_w_pipe: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq ((int) nwritten, 0);
}
END_TEST

START_TEST(test_fopen_wp_pipe)
{
	FILE * f;
	size_t nwritten;

	lsrtest_prepare_pipe ();
	LSR_PROLOG_FOR_TEST ();

	f = fopen (LSR_PIPE_FILENAME, "w+");
	nwritten = lsrtest_get_nwritten ();
	if (f != NULL)
	{
		fclose(f);
	}
	else
	{
		ck_abort_msg("test_fopen_wp_pipe: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq ((int) nwritten, 0);
}
END_TEST
#endif /* LSR_CAN_USE_PIPE */

START_TEST(test_freopen_rr)
{
	FILE * f;
	size_t nwritten;

	LSR_PROLOG_FOR_TEST ();

	f = fopen (LSR_TEST_FILENAME, "r");
	nwritten = lsrtest_get_nwritten ();
	if (f != NULL)
	{
		ck_assert_int_eq ((int) nwritten, 0);
		lsrtest_set_inside_write (0);
		lsrtest_set_nwritten (0);
		lsrtest_set_nwritten_total (0);

		f = freopen (LSR_TEST_FILENAME, "r", f);
		nwritten = lsrtest_get_nwritten ();
		if (f != NULL)
		{
			fclose(f);
		}
		else
		{
			ck_abort_msg("test_freopen_rr: file not re-opened: errno=%d\n", errno);
		}
	}
	else
	{
		ck_abort_msg("test_freopen_rr: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq ((int) nwritten, 0);
}
END_TEST

START_TEST(test_freopen_rw)
{
	FILE * f;
	size_t nwritten;

	LSR_PROLOG_FOR_TEST ();

	f = fopen (LSR_TEST_FILENAME, "r");
	nwritten = lsrtest_get_nwritten ();
	if (f != NULL)
	{
		ck_assert_int_eq ((int) nwritten, 0);
		lsrtest_set_inside_write (0);
		lsrtest_set_nwritten (0);
		lsrtest_set_nwritten_total (0);

		f = freopen (LSR_TEST_FILENAME, "w", f);
		nwritten = lsrtest_get_nwritten ();
		if (f != NULL)
		{
			fclose(f);
		}
		else
		{
			ck_abort_msg("test_freopen_rw: file not re-opened: errno=%d\n", errno);
		}
	}
	else
	{
		ck_abort_msg("test_freopen_rw: file not opened: errno=%d\n", errno);
	}
	/* file already opened and re-opened won't be wiped - fcntl()
	won't allow setting the exclusive lock */
	ck_assert_int_eq ((int) nwritten, 0);
}
END_TEST

START_TEST(test_freopen_rwp)
{
	FILE * f;
	size_t nwritten;

	LSR_PROLOG_FOR_TEST ();

	f = fopen (LSR_TEST_FILENAME, "r");
	nwritten = lsrtest_get_nwritten ();
	if (f != NULL)
	{
		ck_assert_int_eq ((int) nwritten, 0);
		lsrtest_set_inside_write (0);
		lsrtest_set_nwritten (0);
		lsrtest_set_nwritten_total (0);

		f = freopen (LSR_TEST_FILENAME, "w+", f);
		nwritten = lsrtest_get_nwritten ();
		if (f != NULL)
		{
			fclose(f);
		}
		else
		{
			ck_abort_msg("test_freopen_rw: file not re-opened: errno=%d\n", errno);
		}
	}
	else
	{
		ck_abort_msg("test_freopen_rw: file not opened: errno=%d\n", errno);
	}
	/* file already opened and re-opened won't be wiped - fcntl()
	won't allow setting the exclusive lock */
	ck_assert_int_eq ((int) nwritten, 0);
}
END_TEST

START_TEST(test_freopen_rw_banned)
{
	FILE * f;
	size_t nwritten;

	lsrtest_prepare_banned_file ();
	LSR_PROLOG_FOR_TEST ();

	f = fopen (LSR_TEST_FILENAME, "r");
	nwritten = lsrtest_get_nwritten ();
	if (f != NULL)
	{
		ck_assert_int_eq ((int) nwritten, 0);
		lsrtest_set_inside_write (0);
		lsrtest_set_nwritten (0);
		lsrtest_set_nwritten_total (0);

		f = freopen (LSR_TEST_BANNED_FILENAME, "w", f);
		nwritten = lsrtest_get_nwritten ();
		if (f != NULL)
		{
			fclose(f);
		}
		else
		{
			ck_abort_msg("test_freopen_rw_banned: file not re-opened: errno=%d\n", errno);
		}
	}
	else
	{
		ck_abort_msg("test_freopen_rw_banned: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq ((int) nwritten, 0);
}
END_TEST

START_TEST(test_freopen_rwp_banned)
{
	FILE * f;
	size_t nwritten;

	lsrtest_prepare_banned_file ();
	LSR_PROLOG_FOR_TEST ();

	f = fopen (LSR_TEST_FILENAME, "r");
	nwritten = lsrtest_get_nwritten ();
	if (f != NULL)
	{
		ck_assert_int_eq ((int) nwritten, 0);
		lsrtest_set_inside_write (0);
		lsrtest_set_nwritten (0);
		lsrtest_set_nwritten_total (0);

		f = freopen (LSR_TEST_BANNED_FILENAME, "w+", f);
		nwritten = lsrtest_get_nwritten ();
		if (f != NULL)
		{
			fclose(f);
		}
		else
		{
			ck_abort_msg("test_freopen_rw_banned: file not re-opened: errno=%d\n", errno);
		}
	}
	else
	{
		ck_abort_msg("test_freopen_rw_banned: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq ((int) nwritten, 0);
}
END_TEST

START_TEST(test_freopen_rw_stdout)
{
	FILE * f;
	size_t nwritten;

	LSR_PROLOG_FOR_TEST ();

	f = freopen (LSR_TEST_FILENAME, "w", stdout);
	nwritten = lsrtest_get_nwritten ();
	if (f != NULL)
	{
		fclose(f);
	}
	else
	{
		ck_abort_msg("test_freopen_rw_stdout: file not re-opened: errno=%d\n", errno);
	}
	ck_assert_int_eq ((int) nwritten, LSR_TEST_FILE_LENGTH);
}
END_TEST

START_TEST(test_freopen_rwp_stdout)
{
	FILE * f;
	size_t nwritten;

	LSR_PROLOG_FOR_TEST ();

	f = freopen (LSR_TEST_FILENAME, "w+", stdout);
	nwritten = lsrtest_get_nwritten ();
	if (f != NULL)
	{
		fclose(f);
	}
	else
	{
		ck_abort_msg("test_freopen_rw_stdout: file not re-opened: errno=%d\n", errno);
	}
	ck_assert_int_eq ((int) nwritten, LSR_TEST_FILE_LENGTH);
}
END_TEST

START_TEST(test_freopen_rw_stdout_banned)
{
	FILE * f;
	size_t nwritten;

	lsrtest_prepare_banned_file ();
	LSR_PROLOG_FOR_TEST ();

	f = freopen (LSR_TEST_BANNED_FILENAME, "w", stdout);
	nwritten = lsrtest_get_nwritten ();
	if (f != NULL)
	{
		fclose(f);
	}
	else
	{
		ck_abort_msg("test_freopen_rw_stdout_banned: file not re-opened: errno=%d\n", errno);
	}
	ck_assert_int_eq ((int) nwritten, 0);
}
END_TEST

START_TEST(test_freopen_rwp_stdout_banned)
{
	FILE * f;
	size_t nwritten;

	lsrtest_prepare_banned_file ();
	LSR_PROLOG_FOR_TEST ();

	f = freopen (LSR_TEST_BANNED_FILENAME, "w+", stdout);
	nwritten = lsrtest_get_nwritten ();
	if (f != NULL)
	{
		fclose(f);
	}
	else
	{
		ck_abort_msg("test_freopen_rw_stdout_banned: file not re-opened: errno=%d\n", errno);
	}
	ck_assert_int_eq ((int) nwritten, 0);
}
END_TEST

START_TEST(test_freopen_wr)
{
	FILE * f;
	size_t nwritten;

	LSR_PROLOG_FOR_TEST ();

	f = fopen (LSR_TEST_FILENAME, "w");
	nwritten = lsrtest_get_nwritten ();
	if (f != NULL)
	{
		ck_assert_int_eq ((int) nwritten, LSR_TEST_FILE_LENGTH);
		lsrtest_set_inside_write (0);
		lsrtest_set_nwritten (0);
		lsrtest_set_nwritten_total (0);

		f = freopen (LSR_TEST_FILENAME, "r", f);
		nwritten = lsrtest_get_nwritten ();
		if (f != NULL)
		{
			fclose(f);
		}
		else
		{
			ck_abort_msg("test_freopen_wr: file not re-opened: errno=%d\n", errno);
		}
	}
	else
	{
		ck_abort_msg("test_freopen_wr: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq ((int) lsrtest_get_nwritten (), 0);
}
END_TEST

START_TEST(test_freopen_wpr)
{
	FILE * f;
	size_t nwritten;

	LSR_PROLOG_FOR_TEST ();

	f = fopen (LSR_TEST_FILENAME, "w+");
	nwritten = lsrtest_get_nwritten ();
	if (f != NULL)
	{
		ck_assert_int_eq ((int) nwritten, LSR_TEST_FILE_LENGTH);
		lsrtest_set_inside_write (0);
		lsrtest_set_nwritten (0);
		lsrtest_set_nwritten_total (0);

		f = freopen (LSR_TEST_FILENAME, "r", f);
		nwritten = lsrtest_get_nwritten ();
		if (f != NULL)
		{
			fclose(f);
		}
		else
		{
			ck_abort_msg("test_freopen_wr: file not re-opened: errno=%d\n", errno);
		}
	}
	else
	{
		ck_abort_msg("test_freopen_wr: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq ((int) lsrtest_get_nwritten (), 0);
}
END_TEST

START_TEST(test_freopen_ww)
{
	FILE * f;
	size_t nwritten;

	LSR_PROLOG_FOR_TEST ();

	f = fopen (LSR_TEST_FILENAME, "w");
	nwritten = lsrtest_get_nwritten ();
	if (f != NULL)
	{
		ck_assert_int_eq ((int) nwritten, LSR_TEST_FILE_LENGTH);
		lsrtest_set_inside_write (0);
		lsrtest_set_nwritten (0);
		lsrtest_set_nwritten_total (0);

		f = freopen (LSR_TEST_FILENAME, "w", f);
		nwritten = lsrtest_get_nwritten ();
		if (f != NULL)
		{
			fclose(f);
		}
		else
		{
			ck_abort_msg("test_freopen_ww: file not re-opened: errno=%d\n", errno);
		}
	}
	else
	{
		ck_abort_msg("test_freopen_ww: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq ((int) nwritten, 0);
}
END_TEST

START_TEST(test_freopen_wpw)
{
	FILE * f;
	size_t nwritten;

	LSR_PROLOG_FOR_TEST ();

	f = fopen (LSR_TEST_FILENAME, "w+");
	nwritten = lsrtest_get_nwritten ();
	if (f != NULL)
	{
		ck_assert_int_eq ((int) nwritten, LSR_TEST_FILE_LENGTH);
		lsrtest_set_inside_write (0);
		lsrtest_set_nwritten (0);
		lsrtest_set_nwritten_total (0);

		f = freopen (LSR_TEST_FILENAME, "w", f);
		nwritten = lsrtest_get_nwritten ();
		if (f != NULL)
		{
			fclose(f);
		}
		else
		{
			ck_abort_msg("test_freopen_ww: file not re-opened: errno=%d\n", errno);
		}
	}
	else
	{
		ck_abort_msg("test_freopen_ww: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq ((int) nwritten, 0);
}
END_TEST

START_TEST(test_freopen_wwp)
{
	FILE * f;
	size_t nwritten;

	LSR_PROLOG_FOR_TEST ();

	f = fopen (LSR_TEST_FILENAME, "w");
	nwritten = lsrtest_get_nwritten ();
	if (f != NULL)
	{
		ck_assert_int_eq ((int) nwritten, LSR_TEST_FILE_LENGTH);
		lsrtest_set_inside_write (0);
		lsrtest_set_nwritten (0);
		lsrtest_set_nwritten_total (0);

		f = freopen (LSR_TEST_FILENAME, "w+", f);
		nwritten = lsrtest_get_nwritten ();
		if (f != NULL)
		{
			fclose(f);
		}
		else
		{
			ck_abort_msg("test_freopen_ww: file not re-opened: errno=%d\n", errno);
		}
	}
	else
	{
		ck_abort_msg("test_freopen_ww: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq ((int) nwritten, 0);
}
END_TEST

#ifdef LSR_CAN_USE_PIPE
START_TEST(test_freopen_ww_pipe)
{
	FILE * f;
	size_t nwritten;

	lsrtest_prepare_pipe ();
	LSR_PROLOG_FOR_TEST ();

	f = fopen (LSR_TEST_FILENAME, "w");
	nwritten = lsrtest_get_nwritten ();
	if (f != NULL)
	{
		ck_assert_int_eq ((int) nwritten, LSR_TEST_FILE_LENGTH);
		lsrtest_set_inside_write (0);
		lsrtest_set_nwritten (0);
		lsrtest_set_nwritten_total (0);

		f = freopen (LSR_PIPE_FILENAME, "w", f);
		nwritten = lsrtest_get_nwritten ();
		if (f != NULL)
		{
			fclose(f);
		}
		else
		{
			ck_abort_msg("test_freopen_ww: file not re-opened: errno=%d\n", errno);
		}
	}
	else
	{
		ck_abort_msg("test_freopen_ww: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq ((int) nwritten, 0);
}
END_TEST
#endif /* LSR_CAN_USE_PIPE */

START_TEST(test_freopen_ww_banned1)
{
	FILE * f;
	size_t nwritten;

	lsrtest_prepare_banned_file ();
	LSR_PROLOG_FOR_TEST ();

	f = fopen (LSR_TEST_BANNED_FILENAME, "w");
	nwritten = lsrtest_get_nwritten ();
	if (f != NULL)
	{
		ck_assert_int_eq ((int) nwritten, 0);
		lsrtest_set_inside_write (0);
		lsrtest_set_nwritten (0);
		lsrtest_set_nwritten_total (0);

		f = freopen (LSR_TEST_FILENAME, "w", f);
		nwritten = lsrtest_get_nwritten ();
		if (f != NULL)
		{
			fclose(f);
		}
		else
		{
			ck_abort_msg("test_freopen_ww_banned1: file not re-opened: errno=%d\n", errno);
		}
	}
	else
	{
		ck_abort_msg("test_freopen_ww_banned1: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq ((int) nwritten, LSR_TEST_FILE_LENGTH);
}
END_TEST

START_TEST(test_freopen_wpw_banned1)
{
	FILE * f;
	size_t nwritten;

	lsrtest_prepare_banned_file ();
	LSR_PROLOG_FOR_TEST ();

	f = fopen (LSR_TEST_BANNED_FILENAME, "w+");
	nwritten = lsrtest_get_nwritten ();
	if (f != NULL)
	{
		ck_assert_int_eq ((int) nwritten, 0);
		lsrtest_set_inside_write (0);
		lsrtest_set_nwritten (0);
		lsrtest_set_nwritten_total (0);

		f = freopen (LSR_TEST_FILENAME, "w", f);
		nwritten = lsrtest_get_nwritten ();
		if (f != NULL)
		{
			fclose(f);
		}
		else
		{
			ck_abort_msg("test_freopen_ww_banned1: file not re-opened: errno=%d\n", errno);
		}
	}
	else
	{
		ck_abort_msg("test_freopen_ww_banned1: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq ((int) nwritten, LSR_TEST_FILE_LENGTH);
}
END_TEST

START_TEST(test_freopen_wwp_banned1)
{
	FILE * f;
	size_t nwritten;

	lsrtest_prepare_banned_file ();
	LSR_PROLOG_FOR_TEST ();

	f = fopen (LSR_TEST_BANNED_FILENAME, "w");
	nwritten = lsrtest_get_nwritten ();
	if (f != NULL)
	{
		ck_assert_int_eq ((int) nwritten, 0);
		lsrtest_set_inside_write (0);
		lsrtest_set_nwritten (0);
		lsrtest_set_nwritten_total (0);

		f = freopen (LSR_TEST_FILENAME, "w+", f);
		nwritten = lsrtest_get_nwritten ();
		if (f != NULL)
		{
			fclose(f);
		}
		else
		{
			ck_abort_msg("test_freopen_ww_banned1: file not re-opened: errno=%d\n", errno);
		}
	}
	else
	{
		ck_abort_msg("test_freopen_ww_banned1: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq ((int) nwritten, LSR_TEST_FILE_LENGTH);
}
END_TEST

START_TEST(test_freopen_ww_banned1_link)
{
	FILE * f;
	size_t nwritten;
	int r;

	lsrtest_prepare_banned_file ();
	LSR_PROLOG_FOR_TEST ();

	r = symlink (LSR_TEST_FILENAME, LSR_LINK_FILENAME);
	if (r != 0)
	{
		ck_abort_msg("test_freopen_ww_banned1_link: link could not have been created: errno=%d, r=%d\n", errno, r);
	}
	f = fopen (LSR_TEST_BANNED_FILENAME, "w");
	nwritten = lsrtest_get_nwritten ();
	if (f != NULL)
	{
		ck_assert_int_eq ((int) nwritten, 0);
		lsrtest_set_inside_write (0);
		lsrtest_set_nwritten (0);
		lsrtest_set_nwritten_total (0);

		f = freopen (LSR_LINK_FILENAME, "w", f);
		nwritten = lsrtest_get_nwritten ();
		if (f != NULL)
		{
			fclose(f);
		}
		else
		{
			ck_abort_msg("test_freopen_ww_banned1_link: file not re-opened: errno=%d\n", errno);
		}
	}
	else
	{
		ck_abort_msg("test_freopen_ww_banned1_link: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq ((int) nwritten, LSR_TEST_FILE_LENGTH);
}
END_TEST

START_TEST(test_freopen_wpw_banned1_link)
{
	FILE * f;
	size_t nwritten;
	int r;

	lsrtest_prepare_banned_file ();
	LSR_PROLOG_FOR_TEST ();

	r = symlink (LSR_TEST_FILENAME, LSR_LINK_FILENAME);
	if (r != 0)
	{
		ck_abort_msg("test_freopen_wpw_banned1_link: link could not have been created: errno=%d, r=%d\n", errno, r);
	}
	f = fopen (LSR_TEST_BANNED_FILENAME, "w+");
	nwritten = lsrtest_get_nwritten ();
	if (f != NULL)
	{
		ck_assert_int_eq ((int) nwritten, 0);
		lsrtest_set_inside_write (0);
		lsrtest_set_nwritten (0);
		lsrtest_set_nwritten_total (0);

		f = freopen (LSR_LINK_FILENAME, "w", f);
		nwritten = lsrtest_get_nwritten ();
		if (f != NULL)
		{
			fclose(f);
		}
		else
		{
			ck_abort_msg("test_freopen_wpw_banned1_link: file not re-opened: errno=%d\n", errno);
		}
	}
	else
	{
		ck_abort_msg("test_freopen_wpw_banned1_link: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq ((int) nwritten, LSR_TEST_FILE_LENGTH);
}
END_TEST

START_TEST(test_freopen_wwp_banned1_link)
{
	FILE * f;
	size_t nwritten;
	int r;

	lsrtest_prepare_banned_file ();
	LSR_PROLOG_FOR_TEST ();

	r = symlink (LSR_TEST_FILENAME, LSR_LINK_FILENAME);
	if (r != 0)
	{
		ck_abort_msg("test_freopen_wwp_banned1_link: link could not have been created: errno=%d, r=%d\n", errno, r);
	}
	f = fopen (LSR_TEST_BANNED_FILENAME, "w");
	nwritten = lsrtest_get_nwritten ();
	if (f != NULL)
	{
		ck_assert_int_eq ((int) nwritten, 0);
		lsrtest_set_inside_write (0);
		lsrtest_set_nwritten (0);
		lsrtest_set_nwritten_total (0);

		f = freopen (LSR_LINK_FILENAME, "w+", f);
		nwritten = lsrtest_get_nwritten ();
		if (f != NULL)
		{
			fclose(f);
		}
		else
		{
			ck_abort_msg("test_freopen_wwp_banned1_link: file not re-opened: errno=%d\n", errno);
		}
	}
	else
	{
		ck_abort_msg("test_freopen_wwp_banned1_link: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq ((int) nwritten, LSR_TEST_FILE_LENGTH);
}
END_TEST

START_TEST(test_freopen_ww_banned2)
{
	FILE * f;
	size_t nwritten;

	lsrtest_prepare_banned_file ();
	LSR_PROLOG_FOR_TEST ();

	f = fopen (LSR_TEST_FILENAME, "w");
	nwritten = lsrtest_get_nwritten ();
	if (f != NULL)
	{
		ck_assert_int_eq ((int) nwritten, LSR_TEST_FILE_LENGTH);
		lsrtest_set_inside_write (0);
		lsrtest_set_nwritten (0);
		lsrtest_set_nwritten_total (0);

		f = freopen (LSR_TEST_BANNED_FILENAME, "w", f);
		nwritten = lsrtest_get_nwritten ();
		if (f != NULL)
		{
			fclose(f);
		}
		else
		{
			ck_abort_msg("test_freopen_ww_banned2: file not re-opened: errno=%d\n", errno);
		}
	}
	else
	{
		ck_abort_msg("test_freopen_ww_banned2: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq ((int) nwritten, 0);
}
END_TEST

START_TEST(test_freopen_wpw_banned2)
{
	FILE * f;
	size_t nwritten;

	lsrtest_prepare_banned_file ();
	LSR_PROLOG_FOR_TEST ();

	f = fopen (LSR_TEST_FILENAME, "w+");
	nwritten = lsrtest_get_nwritten ();
	if (f != NULL)
	{
		ck_assert_int_eq ((int) nwritten, LSR_TEST_FILE_LENGTH);
		lsrtest_set_inside_write (0);
		lsrtest_set_nwritten (0);
		lsrtest_set_nwritten_total (0);

		f = freopen (LSR_TEST_BANNED_FILENAME, "w", f);
		nwritten = lsrtest_get_nwritten ();
		if (f != NULL)
		{
			fclose(f);
		}
		else
		{
			ck_abort_msg("test_freopen_ww_banned2: file not re-opened: errno=%d\n", errno);
		}
	}
	else
	{
		ck_abort_msg("test_freopen_ww_banned2: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq ((int) nwritten, 0);
}
END_TEST

START_TEST(test_freopen_wwp_banned2)
{
	FILE * f;
	size_t nwritten;

	lsrtest_prepare_banned_file ();
	LSR_PROLOG_FOR_TEST ();

	f = fopen (LSR_TEST_FILENAME, "w");
	nwritten = lsrtest_get_nwritten ();
	if (f != NULL)
	{
		ck_assert_int_eq ((int) nwritten, LSR_TEST_FILE_LENGTH);
		lsrtest_set_inside_write (0);
		lsrtest_set_nwritten (0);
		lsrtest_set_nwritten_total (0);

		f = freopen (LSR_TEST_BANNED_FILENAME, "w+", f);
		nwritten = lsrtest_get_nwritten ();
		if (f != NULL)
		{
			fclose(f);
		}
		else
		{
			ck_abort_msg("test_freopen_ww_banned2: file not re-opened: errno=%d\n", errno);
		}
	}
	else
	{
		ck_abort_msg("test_freopen_ww_banned2: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq ((int) nwritten, 0);
}
END_TEST

START_TEST(test_fdopen_r)
{
	int fd;
	FILE * f;
	size_t nwritten;

	LSR_PROLOG_FOR_TEST ();

	fd = open (LSR_TEST_FILENAME, O_RDONLY);
	nwritten = lsrtest_get_nwritten ();
	if (fd >= 0)
	{
		ck_assert_int_eq ((int) nwritten, 0);
		lsrtest_set_inside_write (0);
		lsrtest_set_nwritten (0);
		lsrtest_set_nwritten_total (0);

		f = fdopen (fd, "r");
		nwritten = lsrtest_get_nwritten ();
		if (f != NULL)
		{
			fclose(f);
		}
		else
		{
			ck_abort_msg("test_fdopen_r: file not re-opened: errno=%d\n", errno);
		}
	}
	else
	{
		ck_abort_msg("test_fdopen_r: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq ((int) nwritten, 0);
}
END_TEST

START_TEST(test_fdopen_w)
{
	int fd;
	FILE * f;
	size_t nwritten;

	LSR_PROLOG_FOR_TEST ();

	fd = open (LSR_TEST_FILENAME, O_RDWR);
	nwritten = lsrtest_get_nwritten ();
	if (fd >= 0)
	{
		ck_assert_int_eq ((int) nwritten, 0);
		lsrtest_set_inside_write (0);
		lsrtest_set_nwritten (0);
		lsrtest_set_nwritten_total (0);

		f = fdopen (fd, "w");
		nwritten = lsrtest_get_nwritten ();
		if (f != NULL)
		{
			fclose(f);
		}
		else
		{
			ck_abort_msg("test_fdopen_w: file not re-opened: errno=%d\n", errno);
		}
	}
	else
	{
		ck_abort_msg("test_fdopen_w: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq ((int) nwritten, 0); /* fdopen (w) should not truncate */
}
END_TEST

START_TEST(test_fdopen_wp)
{
	int fd;
	FILE * f;
	size_t nwritten;

	LSR_PROLOG_FOR_TEST ();

	fd = open (LSR_TEST_FILENAME, O_RDWR);
	nwritten = lsrtest_get_nwritten ();
	if (fd >= 0)
	{
		ck_assert_int_eq ((int) nwritten, 0);
		lsrtest_set_inside_write (0);
		lsrtest_set_nwritten (0);
		lsrtest_set_nwritten_total (0);

		f = fdopen (fd, "w+");
		nwritten = lsrtest_get_nwritten ();
		if (f != NULL)
		{
			fclose(f);
		}
		else
		{
			ck_abort_msg("test_fdopen_w: file not re-opened: errno=%d\n", errno);
		}
	}
	else
	{
		ck_abort_msg("test_fdopen_w: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq ((int) nwritten, 0); /* fdopen (w) should not truncate */
}
END_TEST

/* ======================================================= */

static Suite * lsr_create_suite(void)
{
	Suite * s = suite_create("libsecrm_open");

	TCase * tests_fopen = tcase_create("fopen");

	tcase_add_test(tests_fopen, test_fopen_r);
	tcase_add_test(tests_fopen, test_fopen_w);
	tcase_add_test(tests_fopen, test_fopen_wp);
	tcase_add_test(tests_fopen, test_freopen_rr);
	tcase_add_test(tests_fopen, test_freopen_rw);
	tcase_add_test(tests_fopen, test_freopen_rwp);
	tcase_add_test(tests_fopen, test_freopen_wr);
	tcase_add_test(tests_fopen, test_freopen_wpr);
	tcase_add_test(tests_fopen, test_freopen_ww);
	tcase_add_test(tests_fopen, test_freopen_wpw);
	tcase_add_test(tests_fopen, test_freopen_wwp);
	tcase_add_test(tests_fopen, test_fdopen_r);
	tcase_add_test(tests_fopen, test_fdopen_w);
	tcase_add_test(tests_fopen, test_fdopen_wp);

	tcase_add_test(tests_fopen, test_fopen_w_banned);
	tcase_add_test(tests_fopen, test_fopen_wp_banned);
#ifdef HAVE_SYMLINK
	tcase_add_test(tests_fopen, test_fopen_w_link);
	tcase_add_test(tests_fopen, test_fopen_wp_link);
#endif

	tcase_add_test(tests_fopen, test_fopen_w_dev);
	tcase_add_test(tests_fopen, test_fopen_wp_dev);

	tcase_add_test(tests_fopen, test_freopen_rw_banned);
	tcase_add_test(tests_fopen, test_freopen_rwp_banned);
	tcase_add_test(tests_fopen, test_freopen_ww_banned1);
	tcase_add_test(tests_fopen, test_freopen_wpw_banned1);
	tcase_add_test(tests_fopen, test_freopen_wwp_banned1);
	tcase_add_test(tests_fopen, test_freopen_ww_banned2);
	tcase_add_test(tests_fopen, test_freopen_wpw_banned2);
	tcase_add_test(tests_fopen, test_freopen_wwp_banned2);
	tcase_add_test(tests_fopen, test_freopen_rw_stdout);
	tcase_add_test(tests_fopen, test_freopen_rwp_stdout);
	tcase_add_test(tests_fopen, test_freopen_rw_stdout_banned);
	tcase_add_test(tests_fopen, test_freopen_rwp_stdout_banned);
#ifdef HAVE_SYMLINK
	tcase_add_test(tests_fopen, test_freopen_ww_banned1_link);
	tcase_add_test(tests_fopen, test_freopen_wpw_banned1_link);
	tcase_add_test(tests_fopen, test_freopen_wwp_banned1_link);
#endif

	tcase_add_test(tests_fopen, test_fopen_r_proc);
#ifdef LSR_CAN_USE_PIPE
	tcase_add_test(tests_fopen, test_fopen_w_pipe);
	tcase_add_test(tests_fopen, test_fopen_wp_pipe);
	tcase_add_test(tests_fopen, test_freopen_ww_pipe);
#endif

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
