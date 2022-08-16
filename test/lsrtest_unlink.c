/*
 * A library for secure removing files.
 *	-- unit test for file deleting functions.
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

START_TEST(test_unlink_file)
{
	int r;
	size_t nwritten;
	size_t nwritten_tot;
	const char * new_name;
#if (defined HAVE_SYS_STAT_H) && (defined HAVE_ERRNO_H)
	struct stat s;
#endif

	lsrtest_set_inside_write (1);
	printf("test_unlink_file\n");
	lsrtest_set_inside_write (0);
	lsrtest_set_nwritten (0);
	lsrtest_set_nwritten_total (0);

	lsrtest_set_last_name (LSR_TEST_FILENAME);
	r = unlink (LSR_TEST_FILENAME);
	nwritten = lsrtest_get_nwritten ();
	nwritten_tot = lsrtest_get_nwritten_total ();
	if (r != 0)
	{
		fail("test_unlink_file: file could not have been deleted: errno=%d, r=%d\n", errno, r);
	}
#if (defined HAVE_SYS_STAT_H) && (defined HAVE_ERRNO_H)
	r = stat (LSR_TEST_FILENAME, &s);
	if ( (r != -1) || (errno != ENOENT) )
	{
		fail("test_unlink_file: file still exists after delete: errno=%d, r=%d\n", errno, r);
	}
	new_name = lsrtest_get_last_name ();
	r = stat (new_name, &s);
	if ( (r != -1) || (errno != ENOENT) )
	{
		fail("test_unlink_file: renamed file still exists after delete: errno=%d, r=%d\n", errno, r);
	}
#endif
	if ( strcmp (LSR_TEST_FILENAME, new_name) == 0 )
	{
		fail("test_unlink_file: new filename equal to the old one\n");
	}
	ck_assert_int_eq(nwritten_tot, LSR_TEST_FILE_LENGTH * libsecrm_get_number_of_passes());
	ck_assert_int_eq(nwritten, LSR_TEST_FILE_LENGTH);
}
END_TEST

#ifdef HAVE_SYMLINK
START_TEST(test_unlink_link)
{
	int r;
	size_t nwritten;
	const char * new_name;
# if (defined HAVE_SYS_STAT_H) && (defined HAVE_ERRNO_H)
	struct stat s;
# endif

	lsrtest_set_inside_write (1);
	printf("test_unlink_link\n");
	lsrtest_set_inside_write (0);
	lsrtest_set_nwritten (0);
	lsrtest_set_nwritten_total (0);

	r = symlink (LSR_TEST_FILENAME, LSR_LINK_FILENAME);
	if (r != 0)
	{
		fail("test_unlink_link: link could not have been created: errno=%d, r=%d\n", errno, r);
	}
	lsrtest_set_last_name (LSR_LINK_FILENAME);
	r = unlink (LSR_LINK_FILENAME);
	nwritten = lsrtest_get_nwritten ();
	if (r != 0)
	{
		fail("test_unlink_link: link could not have been deleted: errno=%d, r=%d\n", errno, r);
	}
# if (defined HAVE_SYS_STAT_H) && (defined HAVE_ERRNO_H)
	r = stat (LSR_LINK_FILENAME, &s);
	if ( (r != -1) || (errno != ENOENT) )
	{
		fail("test_unlink_link: link still exists after delete: errno=%d, r=%d\n", errno, r);
	}
	new_name = lsrtest_get_last_name ();
	r = stat (new_name, &s);
	if ( (r != -1) || (errno != ENOENT) )
	{
		fail("test_unlink_link: renamed file still exists after delete: errno=%d, r=%d\n", errno, r);
	}
# endif
	/* unlink() skips non-files, so the name shouldn't be changed */
	if ( strcmp (LSR_LINK_FILENAME, new_name) != 0 )
	{
		fail("test_unlink_link: new filename '%s' not equal to the old one '%s'\n", new_name, LSR_LINK_FILENAME);
	}
	ck_assert_int_eq(nwritten, 0);
}
END_TEST
#endif /* HAVE_SYMLINK */

#ifdef HAVE_UNLINKAT
START_TEST(test_unlinkat_file)
{
	int r;
	size_t nwritten;
	const char * new_name;
# if (defined HAVE_SYS_STAT_H) && (defined HAVE_ERRNO_H)
	struct stat s;
# endif

	lsrtest_set_inside_write (1);
	printf("test_unlinkat_file\n");
	lsrtest_set_inside_write (0);
	lsrtest_set_nwritten (0);
	lsrtest_set_nwritten_total (0);

	lsrtest_set_last_name (LSR_TEST_FILENAME);
	r = unlinkat (AT_FDCWD, LSR_TEST_FILENAME, 0);
	nwritten = lsrtest_get_nwritten ();
	if (r != 0)
	{
		fail("test_unlinkat_file: file could not have been deleted: errno=%d, r=%d\n", errno, r);
	}
# if (defined HAVE_SYS_STAT_H) && (defined HAVE_ERRNO_H)
	r = stat (LSR_TEST_FILENAME, &s);
	if ( (r != -1) || (errno != ENOENT) )
	{
		fail("test_unlinkat_file: file still exists after delete: errno=%d, r=%d\n", errno, r);
	}
	new_name = lsrtest_get_last_name ();
	r = stat (new_name, &s);
	if ( (r != -1) || (errno != ENOENT) )
	{
		fail("test_unlinkat_file: renamed file still exists after delete: errno=%d, r=%d\n", errno, r);
	}
# endif
	if ( strcmp (LSR_TEST_FILENAME, new_name) == 0 )
	{
		fail("test_unlinkat_file: new filename equal to the old one\n");
	}
	ck_assert_int_eq(nwritten, LSR_TEST_FILE_LENGTH);
}
END_TEST

START_TEST(test_unlink_banned)
{
	int r;
	size_t nwritten;
	const char * new_name;
#if (defined HAVE_SYS_STAT_H) && (defined HAVE_ERRNO_H)
	struct stat s;
#endif

	lsrtest_set_inside_write (1);
	printf("test_unlink_banned\n");
	lsrtest_prepare_banned_file();
	lsrtest_set_inside_write (0);
	lsrtest_set_nwritten (0);
	lsrtest_set_nwritten_total (0);

	lsrtest_set_last_name (LSR_TEST_BANNED_FILENAME);
	r = unlink (LSR_TEST_BANNED_FILENAME);
	nwritten = lsrtest_get_nwritten ();
	if (r != 0)
	{
		fail("test_unlink_banned: file could not have been deleted: errno=%d, r=%d\n", errno, r);
	}
#if (defined HAVE_SYS_STAT_H) && (defined HAVE_ERRNO_H)
	r = stat (LSR_TEST_BANNED_FILENAME, &s);
	if ( (r != -1) || (errno != ENOENT) )
	{
		fail("test_unlink_banned: file still exists after delete: errno=%d, r=%d\n", errno, r);
	}
#endif
	new_name = lsrtest_get_last_name ();
	if ( strcmp (LSR_TEST_BANNED_FILENAME, new_name) != 0 )
	{
		fail("test_unlink_banned: banned file has been renamed, but shouldn't have been: new_name='%s'\n",
			new_name);
	}
	ck_assert_int_eq(nwritten, 0);
}
END_TEST

START_TEST(test_unlinkat_file_banned)
{
	int r;
	size_t nwritten;
	const char * new_name;
# if (defined HAVE_SYS_STAT_H) && (defined HAVE_ERRNO_H)
	struct stat s;
# endif

	lsrtest_set_inside_write (1);
	printf("test_unlinkat_file_banned\n");
	lsrtest_prepare_banned_file();
	lsrtest_set_inside_write (0);
	lsrtest_set_nwritten (0);
	lsrtest_set_nwritten_total (0);

	lsrtest_set_last_name (LSR_TEST_BANNED_FILENAME);
	r = unlinkat (AT_FDCWD, LSR_TEST_BANNED_FILENAME, 0);
	nwritten = lsrtest_get_nwritten ();
	if (r != 0)
	{
		fail("test_unlinkat_file_banned: file could not have been deleted: errno=%d, r=%d\n", errno, r);
	}
# if (defined HAVE_SYS_STAT_H) && (defined HAVE_ERRNO_H)
	r = stat (LSR_TEST_BANNED_FILENAME, &s);
	if ( (r != -1) || (errno != ENOENT) )
	{
		fail("test_unlinkat_file_banned: file still exists after delete: errno=%d, r=%d\n", errno, r);
	}
	new_name = lsrtest_get_last_name ();
	r = stat (new_name, &s);
	if ( (r != -1) || (errno != ENOENT) )
	{
		fail("test_unlinkat_file_banned: renamed file still exists after delete: errno=%d, r=%d\n", errno, r);
	}
# endif
	if ( strcmp (LSR_TEST_BANNED_FILENAME, new_name) != 0 )
	{
		fail("test_unlinkat_file_banned: banned file has been renamed, but shouldn't have been: new_name='%s'\n",
			new_name);
	}
	ck_assert_int_eq(nwritten, 0);
}
END_TEST
#endif /* HAVE_UNLINKAT */

START_TEST(test_remove)
{
	int r;
	size_t nwritten;
	size_t nwritten_tot;
	const char * new_name;
#if (defined HAVE_SYS_STAT_H) && (defined HAVE_ERRNO_H)
	struct stat s;
#endif

	lsrtest_set_inside_write (1);
	printf("test_remove\n");
	lsrtest_set_inside_write (0);
	lsrtest_set_nwritten (0);
	lsrtest_set_nwritten_total (0);

	lsrtest_set_last_name (LSR_TEST_FILENAME);
	r = remove (LSR_TEST_FILENAME);
	nwritten = lsrtest_get_nwritten ();
	nwritten_tot = lsrtest_get_nwritten_total ();
	if (r != 0)
	{
		fail("test_remove: file could not have been deleted: errno=%d, r=%d\n", errno, r);
	}
#if (defined HAVE_SYS_STAT_H) && (defined HAVE_ERRNO_H)
	r = stat (LSR_TEST_FILENAME, &s);
	if ( (r != -1) || (errno != ENOENT) )
	{
		fail("test_remove: file still exists after delete: errno=%d, r=%d\n", errno, r);
	}
	new_name = lsrtest_get_last_name ();
	r = stat (new_name, &s);
	if ( (r != -1) || (errno != ENOENT) )
	{
		fail("test_remove: renamed file still exists after delete: errno=%d, r=%d\n", errno, r);
	}
#endif
	if ( strcmp (LSR_TEST_FILENAME, new_name) == 0 )
	{
		fail("test_remove: new filename equal to the old one\n");
	}
	ck_assert_int_eq(nwritten_tot, LSR_TEST_FILE_LENGTH * libsecrm_get_number_of_passes());
	ck_assert_int_eq(nwritten, LSR_TEST_FILE_LENGTH);
}
END_TEST

START_TEST(test_remove_banned)
{
	int r;
	size_t nwritten;
	const char * new_name;
#if (defined HAVE_SYS_STAT_H) && (defined HAVE_ERRNO_H)
	struct stat s;
#endif

	lsrtest_set_inside_write (1);
	printf("test_remove_banned\n");
	lsrtest_prepare_banned_file();
	lsrtest_set_inside_write (0);
	lsrtest_set_nwritten (0);
	lsrtest_set_nwritten_total (0);

	lsrtest_set_last_name (LSR_TEST_BANNED_FILENAME);
	r = remove (LSR_TEST_BANNED_FILENAME);
	nwritten = lsrtest_get_nwritten ();
	if (r != 0)
	{
		fail("test_remove_banned: file could not have been deleted: errno=%d, r=%d\n", errno, r);
	}
#if (defined HAVE_SYS_STAT_H) && (defined HAVE_ERRNO_H)
	r = stat (LSR_TEST_BANNED_FILENAME, &s);
	if ( (r != -1) || (errno != ENOENT) )
	{
		fail("test_remove_banned: file still exists after delete: errno=%d, r=%d\n", errno, r);
	}
	new_name = lsrtest_get_last_name ();
	r = stat (new_name, &s);
	if ( (r != -1) || (errno != ENOENT) )
	{
		fail("test_remove_banned: renamed file still exists after delete: errno=%d, r=%d\n", errno, r);
	}
#endif
	if ( strcmp (LSR_TEST_BANNED_FILENAME, new_name) != 0 )
	{
		fail("test_remove_banned: banned file has been renamed, but shouldn't have been: new_name='%s'\n",
			new_name);
	}
	ck_assert_int_eq(nwritten, 0);
}
END_TEST

#ifdef HAVE_MKDIR
START_TEST(test_rmdir)
{
	int r;
	size_t nwritten;
	const char * new_name;
# if (defined HAVE_SYS_STAT_H) && (defined HAVE_ERRNO_H)
	struct stat s;
# endif

	lsrtest_set_inside_write (1);
	printf("test_rmdir\n");
	lsrtest_set_inside_write (0);
	lsrtest_set_nwritten (0);
	lsrtest_set_nwritten_total (0);

	r = mkdir (LSR_TEST_DIRNAME, S_IRUSR|S_IWUSR);
	if (r != 0)
	{
		fail("test_rmdir: directory could not have been created: errno=%d, r=%d\n", errno, r);
	}
	lsrtest_set_last_name (LSR_TEST_DIRNAME);
	r = rmdir (LSR_TEST_DIRNAME);
	nwritten = lsrtest_get_nwritten ();
	if (r != 0)
	{
		fail("test_rmdir: directory could not have been deleted: errno=%d, r=%d\n", errno, r);
	}
# if (defined HAVE_SYS_STAT_H) && (defined HAVE_ERRNO_H)
	r = stat (LSR_TEST_DIRNAME, &s);
	if ( (r != -1) || (errno != ENOENT) )
	{
		fail("test_rmdir: directory still exists after delete: errno=%d, r=%d\n", errno, r);
	}
	new_name = lsrtest_get_last_name ();
	r = stat (new_name, &s);
	if ( (r != -1) || (errno != ENOENT) )
	{
		fail("test_rmdir: renamed directory still exists after delete: errno=%d, r=%d\n", errno, r);
	}
# endif
	if ( strcmp (LSR_TEST_DIRNAME, new_name) == 0 )
	{
		fail("test_rmdir: new directory name equal to the old one\n");
	}
	ck_assert_int_eq(nwritten, 0);
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
#ifdef HAVE_UNLINKAT
	tcase_add_test(tests_del, test_unlinkat_file);
	tcase_add_test(tests_del, test_unlinkat_file_banned);
#endif
#ifdef HAVE_SYMLINK
	tcase_add_test(tests_del, test_unlink_link);
#endif
	tcase_add_test(tests_del, test_remove);
	tcase_add_test(tests_del, test_remove_banned);
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
