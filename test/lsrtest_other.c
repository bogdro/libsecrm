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

#include "lsrtest_common.h"

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

#if (defined HAVE_DLFCN_H) && ((defined HAVE_DLSYM) || (defined HAVE_LIBDL))
/* ======================================================= */

START_TEST(test_symb)
{
	void * ptr;
	LSR_PROLOG_FOR_TEST();

	ptr = dlsym  (RTLD_NEXT, "generic_fopen");
	if (ptr != NULL)
	{
		ck_abort_msg("test_symb: symbol found\n");
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
		ck_abort_msg("test_symb_var: symbol found\n");
	}
}
END_TEST

/* ======================================================= */
#endif /* (defined HAVE_DLFCN_H) && ((defined HAVE_DLSYM) || (defined HAVE_LIBDL)) */

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
	unsigned long int pat_no;
#ifdef ALL_PASSES_ZERO
	unsigned char marker = '\x55';
#else
	unsigned char marker = ':';
#endif

	/* try to pick a non-random pattern */
#ifdef LSR_WANT_RANDOM
	pat_no = 1;
#else
# ifdef LSR_WANT_SCHNEIER
	pat_no = 0;
# else
#  ifdef LSR_WANT_DOD
	pat_no = 0;
#  else
	pat_no = 4;
#  endif
# endif
#endif

	LSR_PROLOG_FOR_TEST();

	for ( i = 0; i < LSR_NPAT; i++ )
	{
		for ( j = 0; j < sizeof (buffer); j++ )
		{
			buffer[j] = marker;
		}
		__lsr_fill_buffer (pat_no, &buffer[OFFSET], i, selected);
		for ( j = 0; j < OFFSET; j++ )
		{
			if ( buffer[j] != marker )
			{
				ck_abort_msg("test_fill_buffer: iteration %ld, pattern %lu: buffer[%ld] != 0x%x, but should be\n",
					i, pat_no, j, marker);
			}
		}
		if ( i >= 3 )
		{
			/* skip in case the pattern picked the marker as its value
			 * - need to check if the marker wasn't picked in any
			 * of the 3 bytes of the pattern
			 */
			if ( (buffer[OFFSET] != marker)
				&& (buffer[OFFSET + 1] != marker)
				&& (buffer[OFFSET + 2] != marker)
			)
			{
				for ( j = OFFSET; j < i + OFFSET; j++ )
				{
					if ( buffer[j] == marker )
					{
						ck_abort_msg("test_fill_buffer: iteration %ld, pattern %lu: buffer[%ld] == 0x%x, but shouldn't be\n",
							i, pat_no, j, marker);
					}
				}
			}
		}
		for ( j = i + OFFSET; j < sizeof (buffer); j++ )
		{
			if ( buffer[j] != marker )
			{
				ck_abort_msg("test_fill_buffer: iteration %ld, pattern %lu: buffer[%ld] != 0x%x, but should be\n",
					i, pat_no, j, marker);
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

#if (defined HAVE_DLFCN_H) && ((defined HAVE_DLSYM) || (defined HAVE_LIBDL))
	tcase_add_test(tests_other, test_symb);
	tcase_add_test(tests_other, test_symb_var);
#endif
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
