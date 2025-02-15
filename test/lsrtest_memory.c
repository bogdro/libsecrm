/*
 * LibSecRm - A library for secure removing files.
 *	-- unit test for memory functions.
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

#ifdef HAVE_MALLOC_H
# include <malloc.h>
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif

/* ======================================================= */

#ifdef HAVE_MALLOC
START_TEST(test_malloc)
{
	void * p;

	LSR_PROLOG_FOR_TEST();

	p = malloc (10);
	if (p != NULL)
	{
		free(p);
	}
	else
	{
		ck_abort_msg("test_malloc: memory not allocated: errno=%d\n", errno);
	}
}
END_TEST
#endif /* HAVE_MALLOC */

START_TEST(test_valloc)
{
	void * p;

	LSR_PROLOG_FOR_TEST();

	p = valloc (10);
	if (p == NULL)
	{
		ck_abort_msg("test_valloc: memory not allocated: errno=%d\n", errno);
	}
	/* pointer returned by valloc is not officially safe to be used with free(p) */
#ifdef __GLIBC__
	free (p);
#endif
}
END_TEST

START_TEST(test_pvalloc)
{
	void * p;

	LSR_PROLOG_FOR_TEST();

	p = pvalloc (10);
	if (p == NULL)
	{
		ck_abort_msg("test_pvalloc: memory not allocated: errno=%d\n", errno);
	}
	/* pointer returned by pvalloc is not officially safe to be used with free(p) */
#ifdef __GLIBC__
	free (p);
#endif
}
END_TEST

#ifdef HAVE_SBRK
START_TEST(test_sbrk)
{
	void * p;

	LSR_PROLOG_FOR_TEST();

	p = sbrk (10);
	if (p == (void *) -1)
	{
		ck_abort_msg("test_sbrk: memory not allocated: errno=%d\n", errno);
	}
}
END_TEST
#endif

#ifdef HAVE_BRK
START_TEST(test_brk)
{
	int r;

	LSR_PROLOG_FOR_TEST();

	r = brk ((char *)sbrk(0)+10);
	if (r == -1)
	{
		ck_abort_msg("test_brk: memory not allocated: errno=%d\n", errno);
	}
}
END_TEST
#endif

#ifdef HAVE_MEMALIGN
START_TEST(test_memalign)
{
	void * p;

	LSR_PROLOG_FOR_TEST();

	p = memalign (8, 10);
	if (p == NULL)
	{
		ck_abort_msg("test_memalign: memory not allocated: errno=%d\n", errno);
	}
	/* pointer returned by memalign is not officially safe to be used with free(p) */
#ifdef __GLIBC__
	free (p);
#endif
}
END_TEST
#endif

#ifdef HAVE_ALIGNED_ALLOC
START_TEST(test_aligned_alloc)
{
	void * p;

	LSR_PROLOG_FOR_TEST();

	p = aligned_alloc (8, 16);
	if (p == NULL)
	{
		ck_abort_msg("test_aligned_alloc: memory not allocated: errno=%d\n", errno);
	}
	/* pointer returned by aligned_alloc is not officially safe to be used with free(p) */
#ifdef __GLIBC__
	free (p);
#endif
}
END_TEST
#endif

#ifdef HAVE_POSIX_MEMALIGN
START_TEST(test_posix_memalign)
{
	void * p = NULL;
	int r;

	LSR_PROLOG_FOR_TEST();

	r = posix_memalign (&p, 8, 10);
	if (p != NULL)
	{
		free(p);
	}
	else
	{
		ck_abort_msg("test_posix_memalign: memory not allocated: errno=%d\n", errno);
	}
	ck_assert_int_ne(r, -1);
}
END_TEST
#endif

/* ======================================================= */

static Suite * lsr_create_suite(void)
{
	Suite * s = suite_create("libsecrm_memory");

	TCase * tests_mem = tcase_create("memory");

#ifdef HAVE_MALLOC
	tcase_add_test(tests_mem, test_malloc);
#endif
	tcase_add_test(tests_mem, test_valloc);
	tcase_add_test(tests_mem, test_pvalloc);
#ifdef HAVE_SBRK
	tcase_add_test(tests_mem, test_sbrk);
#endif
#ifdef HAVE_BRK
	tcase_add_test(tests_mem, test_brk);
#endif
#ifdef HAVE_MEMALIGN
	tcase_add_test(tests_mem, test_memalign);
#endif
#ifdef HAVE_ALIGNED_ALLOC
	tcase_add_test(tests_mem, test_aligned_alloc);
#endif
#ifdef HAVE_POSIX_MEMALIGN
	tcase_add_test(tests_mem, test_posix_memalign);
#endif

	/* set 30-second timeouts */
	tcase_set_timeout(tests_mem, 30);

	suite_add_tcase(s, tests_mem);

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
