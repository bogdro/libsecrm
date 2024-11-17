/*
 * LibSecRm - A library for secure removing files.
 *	-- unit test for file creation functions.
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

START_TEST(test_creat)
{
	int fd;
	size_t nwritten;

	LSR_PROLOG_FOR_TEST();

	fd = creat(LSR_TEST_FILENAME, S_IRUSR|S_IWUSR);
	nwritten = lsrtest_get_nwritten ();
	if (fd >= 0)
	{
		close(fd);
	}
	else
	{
		ck_abort_msg("test_creat: file not created: errno=%d\n", errno);
	}
	ck_assert_int_eq((int) nwritten, LSR_TEST_FILE_LENGTH);
}
END_TEST

/* ======================================================= */

static Suite * lsr_create_suite(void)
{
	Suite * s = suite_create("libsecrm_creat");

	TCase * tests_creat = tcase_create("creat");

	tcase_add_test(tests_creat, test_creat);

	lsrtest_add_fixtures (tests_creat);

	/* set 30-second timeouts */
	tcase_set_timeout(tests_creat, 30);

	suite_add_tcase(s, tests_creat);

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
