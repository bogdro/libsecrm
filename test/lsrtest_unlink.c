/*
 * LibSecRm - A library for secure removing files.
 *	-- unit test for file deleting functions.
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

#define MODE_USE_UNLINK 1
#define MODE_USE_UNLINKAT 2
#define MODE_USE_RMDIR 3
#define MODE_USE_REMOVE 4

static int unlink_and_verify (const char filename[],
	size_t * const nwritten, size_t * const nwritten_tot,
	int mode, int equal_names)
{
	int r = -1;
	const char * new_name = NULL;
#if (defined HAVE_SYS_STAT_H) && (defined HAVE_ERRNO_H)
	struct stat s;
#endif

	if ( filename == NULL )
	{
		ck_abort_msg("unlink_and_verify: invalid parameter\n");
	}
	lsrtest_set_last_name (filename);
	if ( mode == MODE_USE_UNLINK )
	{
		r = unlink (filename);
	}
	else if ( mode == MODE_USE_UNLINKAT )
	{
		r = unlinkat (AT_FDCWD, filename, 0);
	}
	else if ( mode == MODE_USE_RMDIR )
	{
		r = rmdir (filename);
	}
	else if ( mode == MODE_USE_REMOVE )
	{
		r = remove (filename);
	}
	else
	{
		ck_abort_msg("unlink_and_verify: invalid mode %d\n", mode);
	}

	if ( nwritten != NULL )
	{
		*nwritten = lsrtest_get_nwritten ();
	}
	if ( nwritten_tot != NULL )
	{
		*nwritten_tot = lsrtest_get_nwritten_total ();
	}
	if ( r != 0 )
	{
		ck_abort_msg("file could not have been deleted: errno=%d, r=%d\n", errno, r);
	}
#if (defined HAVE_SYS_STAT_H) && (defined HAVE_ERRNO_H)
	r = stat (filename, &s);
	if ( (r != -1) || (errno != ENOENT) )
	{
		ck_abort_msg("file still exists after delete: errno=%d, r=%d\n", errno, r);
	}
	new_name = lsrtest_get_last_name ();
	r = stat (new_name, &s);
	if ( (r != -1) || (errno != ENOENT) )
	{
		ck_abort_msg("renamed file still exists after delete: errno=%d, r=%d\n", errno, r);
	}
#endif
	if ( equal_names != 0 )
	{
		if ( strcmp (filename, new_name) == 0 )
		{
			ck_abort_msg("new filename equal to the old one\n");
		}
	}
	else
	{
		if ( strcmp (filename, new_name) != 0 )
		{
			ck_abort_msg("new filename '%s' not equal to the old one '%s'\n", new_name, filename);
		}
	}
	return 0;
}

/* ======================================================= */

START_TEST(test_unlink_file)
{
	size_t nwritten;
	size_t nwritten_tot;

	LSR_PROLOG_FOR_TEST();

	if ( unlink_and_verify (LSR_TEST_FILENAME, &nwritten,
		&nwritten_tot, MODE_USE_UNLINK, 1) != 0 )
	{
		return;
	}

	ck_assert_int_eq((int) nwritten_tot, (int)(LSR_TEST_FILE_LENGTH * (int)libsecrm_get_number_of_passes()));
	ck_assert_int_eq((int) nwritten, LSR_TEST_FILE_LENGTH);
}
END_TEST

#ifdef HAVE_SYMLINK
START_TEST(test_unlink_link)
{
	int r;
	size_t nwritten;

	LSR_PROLOG_FOR_TEST();

	r = symlink (LSR_TEST_FILENAME, LSR_LINK_FILENAME);
	if (r != 0)
	{
		ck_abort_msg("test_unlink_link: link could not have been created: errno=%d, r=%d\n", errno, r);
	}
	if ( unlink_and_verify (LSR_LINK_FILENAME, &nwritten,
		NULL, MODE_USE_UNLINK,
		/* unlink() skips non-files, so the name shouldn't be changed */ 0) != 0 )
	{
		return;
	}

	ck_assert_int_eq((int) nwritten, 0);
}
END_TEST
#endif /* HAVE_SYMLINK */

START_TEST(test_unlink_banned)
{
	size_t nwritten;

	lsrtest_prepare_banned_file();
	LSR_PROLOG_FOR_TEST();

	if ( unlink_and_verify (LSR_TEST_BANNED_FILENAME, &nwritten,
		NULL, MODE_USE_UNLINK, 0) != 0 )
	{
		return;
	}

	ck_assert_int_eq((int) nwritten, 0);
}
END_TEST

#ifdef LSR_CAN_USE_PIPE
START_TEST(test_unlink_pipe)
{
	size_t nwritten;

	lsrtest_prepare_pipe ();
	LSR_PROLOG_FOR_TEST();

	if ( unlink_and_verify (LSR_PIPE_FILENAME, &nwritten,
		NULL, MODE_USE_UNLINK,
		/* unlink() skips non-files, so the name shouldn't be changed */ 0) != 0 )
	{
		return;
	}

	ck_assert_int_eq((int) nwritten, 0);
}
END_TEST
#endif /* LSR_CAN_USE_PIPE */

#ifdef HAVE_UNLINKAT
START_TEST(test_unlinkat_file)
{
	size_t nwritten;

	LSR_PROLOG_FOR_TEST();

	if ( unlink_and_verify (LSR_TEST_FILENAME, &nwritten,
		NULL, MODE_USE_UNLINKAT, 1) != 0 )
	{
		return;
	}

	ck_assert_int_eq((int) nwritten, LSR_TEST_FILE_LENGTH);
}
END_TEST

#ifdef HAVE_SYMLINK
START_TEST(test_unlinkat_link)
{
	int r;
	size_t nwritten;

	LSR_PROLOG_FOR_TEST();

	r = symlink (LSR_TEST_FILENAME, LSR_LINK_FILENAME);
	if (r != 0)
	{
		ck_abort_msg("test_unlinkat_link: link could not have been created: errno=%d, r=%d\n", errno, r);
	}
	if ( unlink_and_verify (LSR_LINK_FILENAME, &nwritten,
		NULL, MODE_USE_UNLINKAT, 0) != 0 )
	{
		return;
	}

	ck_assert_int_eq((int) nwritten, 0);
}
END_TEST
#endif /* HAVE_SYMLINK */

START_TEST(test_unlinkat_file_banned)
{
	size_t nwritten;

	lsrtest_prepare_banned_file();
	LSR_PROLOG_FOR_TEST();

	if ( unlink_and_verify (LSR_TEST_BANNED_FILENAME, &nwritten,
		NULL, MODE_USE_UNLINKAT, 0) != 0 )
	{
		return;
	}

	ck_assert_int_eq((int) nwritten, 0);
}
END_TEST

# ifdef LSR_CAN_USE_PIPE
START_TEST(test_unlinkat_pipe)
{
	size_t nwritten;

	lsrtest_prepare_pipe ();
	LSR_PROLOG_FOR_TEST();

	if ( unlink_and_verify (LSR_PIPE_FILENAME, &nwritten,
		NULL, MODE_USE_UNLINKAT, 1) != 0 )
	{
		return;
	}

	ck_assert_int_eq((int) nwritten, LSR_TEST_FILE_LENGTH);
}
END_TEST
# endif /* LSR_CAN_USE_PIPE */
#endif /* HAVE_UNLINKAT */

START_TEST(test_remove_file)
{
	size_t nwritten;
	size_t nwritten_tot;

	LSR_PROLOG_FOR_TEST();

	if ( unlink_and_verify (LSR_TEST_FILENAME, &nwritten,
		&nwritten_tot, MODE_USE_REMOVE, 1) != 0 )
	{
		return;
	}

	ck_assert_int_eq((int) nwritten_tot, (int)(LSR_TEST_FILE_LENGTH * (int)libsecrm_get_number_of_passes()));
	ck_assert_int_eq((int) nwritten, LSR_TEST_FILE_LENGTH);
}
END_TEST

START_TEST(test_remove_link)
{
	int r;
	size_t nwritten;
	size_t nwritten_tot;

	LSR_PROLOG_FOR_TEST();

	r = symlink (LSR_TEST_FILENAME, LSR_LINK_FILENAME);
	if (r != 0)
	{
		ck_abort_msg("test_remove_link: link could not have been created: errno=%d, r=%d\n", errno, r);
	}
	if ( unlink_and_verify (LSR_LINK_FILENAME, &nwritten,
		&nwritten_tot, MODE_USE_REMOVE, 0) != 0 )
	{
		return;
	}

	ck_assert_int_eq((int) nwritten_tot, 0);
	ck_assert_int_eq((int) nwritten, 0);
}
END_TEST

START_TEST(test_remove_banned)
{
	size_t nwritten;

	lsrtest_prepare_banned_file();
	LSR_PROLOG_FOR_TEST();

	if ( unlink_and_verify (LSR_TEST_BANNED_FILENAME, &nwritten,
		NULL, MODE_USE_REMOVE, 0) != 0 )
	{
		return;
	}

	ck_assert_int_eq((int) nwritten, 0);
}
END_TEST

#ifdef LSR_CAN_USE_PIPE
START_TEST(test_remove_pipe)
{
	size_t nwritten;
	size_t nwritten_tot;

	lsrtest_prepare_pipe ();
	LSR_PROLOG_FOR_TEST();

	if ( unlink_and_verify (LSR_PIPE_FILENAME, &nwritten,
		&nwritten_tot, MODE_USE_REMOVE, 1) != 0 )
	{
		return;
	}

	ck_assert_int_eq((int) nwritten_tot, (int)(LSR_TEST_FILE_LENGTH * (int)libsecrm_get_number_of_passes()));
	ck_assert_int_eq((int) nwritten, LSR_TEST_FILE_LENGTH);
}
END_TEST
#endif /* LSR_CAN_USE_PIPE */

#ifdef HAVE_MKDIR
START_TEST(test_remove_dir)
{
	int r;
	size_t nwritten;

	LSR_PROLOG_FOR_TEST();

	r = mkdir (LSR_TEST_DIRNAME, S_IRUSR|S_IWUSR);
	if (r != 0)
	{
		ck_abort_msg("test_rmdir: directory could not have been created: errno=%d, r=%d\n", errno, r);
	}
	if ( unlink_and_verify (LSR_TEST_DIRNAME, &nwritten,
		NULL, MODE_USE_REMOVE, 0) != 0 )
	{
		return;
	}

	ck_assert_int_eq((int) nwritten, 0);
}
END_TEST

START_TEST(test_rmdir)
{
	int r;
	size_t nwritten;

	LSR_PROLOG_FOR_TEST();

	r = mkdir (LSR_TEST_DIRNAME, S_IRUSR|S_IWUSR);
	if (r != 0)
	{
		ck_abort_msg("test_rmdir: directory could not have been created: errno=%d, r=%d\n", errno, r);
	}
	if ( unlink_and_verify (LSR_TEST_DIRNAME, &nwritten,
		NULL, MODE_USE_RMDIR, 1) != 0 )
	{
		return;
	}

	ck_assert_int_eq((int) nwritten, 0);
}
END_TEST
#endif /* HAVE_MKDIR */

/* ======================================================= */

static Suite * lsr_create_suite(void)
{
	Suite * s = suite_create("libsecrm_delete");

	TCase * tests_del = tcase_create("delete");

	tcase_add_test(tests_del, test_unlink_file);
	tcase_add_test(tests_del, test_unlink_banned);
#ifdef HAVE_SYMLINK
	tcase_add_test(tests_del, test_unlink_link);
#endif
#ifdef LSR_CAN_USE_PIPE
	tcase_add_test(tests_del, test_unlink_pipe);
#endif

#ifdef HAVE_UNLINKAT
	tcase_add_test(tests_del, test_unlinkat_file);
	tcase_add_test(tests_del, test_unlinkat_file_banned);
# ifdef HAVE_SYMLINK
	tcase_add_test(tests_del, test_unlinkat_link);
# endif
# ifdef LSR_CAN_USE_PIPE
	tcase_add_test(tests_del, test_unlinkat_pipe);
# endif
#endif

	tcase_add_test(tests_del, test_remove_file);
#ifdef HAVE_SYMLINK
	tcase_add_test(tests_del, test_remove_link);
#endif
	tcase_add_test(tests_del, test_remove_banned);
#ifdef LSR_CAN_USE_PIPE
	tcase_add_test(tests_del, test_remove_pipe);
#endif
#ifdef HAVE_MKDIR
	tcase_add_test(tests_del, test_remove_dir);
#endif

#ifdef HAVE_MKDIR
	tcase_add_test(tests_del, test_rmdir);
#endif

	lsrtest_add_fixtures (tests_del);

	/* set 30-second timeouts */
	tcase_set_timeout(tests_del, 30);

	suite_add_tcase(s, tests_del);

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
