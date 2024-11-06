/*
 * LibSecRm - A library for secure removing files.
 *	-- other unit tests.
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

#include <stdio.h>

#ifdef HAVE_ERRNO_H
# include <errno.h>
#else
static int errno = -1;
#endif

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif

#ifdef HAVE_STRING_H
# if (!defined STDC_HEADERS) && (defined HAVE_MEMORY_H)
#  include <memory.h>
# endif
# include <string.h>
#endif

#include "lsr_priv.h"

/* ======================================================= */

START_TEST(test_symb)
{
	void * ptr;
	LSR_PROLOG_FOR_TEST();

	ptr = dlsym  (RTLD_NEXT, "generic_fopen");
	if (ptr != NULL)
	{
		fail("test_symb: symbol found\n");
	}
}
END_TEST

/* ======================================================= */

START_TEST(test_symb_var)
{
	void * ptr;

	LSR_PROLOG_FOR_TEST();
	ptr = dlsym (RTLD_NEXT, "patterns_random");
	if (ptr != NULL)
	{
		fail("test_symb_var: symbol found\n");
	}
}
END_TEST

/* ======================================================= */

START_TEST(test_iter_env)
{
	char * env_niter;
	unsigned long int passes;

	LSR_PROLOG_FOR_TEST();
	env_niter = getenv (LSR_ITERATIONS_ENV);
	if ( env_niter != NULL )
	{
		errno = 0;
		passes = strtoul (env_niter, NULL, 10);
		if ( errno == 0 )
		{
			ck_assert_uint_eq(passes, __lsr_get_npasses());
		}
		/* don't do anything if can't be parsed */
	}
}
END_TEST

/* ======================================================= */

START_TEST(test_fill_buffer)
{
#define OFFSET 20
	unsigned char buffer[100];
	size_t i, j;
	int selected[LSR_NPAT] = {0};
#ifdef ALL_PASSES_ZERO
	unsigned char marker = '\x55';
#else
	unsigned char marker = '\0';
#endif
	LSR_PROLOG_FOR_TEST();

	for ( i = 0; i < 20; i++ )
	{
		for ( j = 0; j < sizeof (buffer); j++ )
		{
			buffer[j] = marker;
		}
		__lsr_fill_buffer (0, &buffer[OFFSET], i, selected);
		for ( j = 0; j < OFFSET; j++ )
		{
			if ( buffer[j] != marker )
			{
				fail("test_fill_buffer: iteration %ld: buffer[%ld] != %c (0x%x), but should be\n", i, j, marker, marker);
			}
		}
		for ( j = 0; j < i; j++ )
		{
			if ( buffer[OFFSET + j] == marker )
			{
				fail("test_fill_buffer: iteration %ld: buffer[%ld] == %c (0x%x), but shouldn't be\n", i, j, marker, marker);
			}
		}
		for ( j = i + OFFSET; j < sizeof (buffer); j++ )
		{
			if ( buffer[j] != marker )
			{
				fail("test_fill_buffer: iteration %ld: buffer[%ld] != %c (0x%x), but should be\n", i, j, marker, marker);
			}
		}
	}
}
END_TEST

/* ======================================================= */

static Suite * lsr_create_suite(void)
{
	Suite * s = suite_create("libsecrm_other");

	TCase * tests_other = tcase_create("other");

	tcase_add_test(tests_other, test_symb);
	tcase_add_test(tests_other, test_symb_var);
	tcase_add_test(tests_other, test_fill_buffer);
	tcase_add_test(tests_other, test_iter_env);

	lsrtest_add_fixtures (tests_other);

	/* set 30-second timeouts */
	tcase_set_timeout(tests_other, 30);

	suite_add_tcase(s, tests_other);

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
