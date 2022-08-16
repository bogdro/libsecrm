/*
 * A library for secure removing files.
 *	-- unit test for memory functions.
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

/* ======================================================= */

#ifdef HAVE_MALLOC
START_TEST(test_malloc)
{
	void * p;

	lsrtest_set_inside_write (1);
	printf("test_malloc\n");
	lsrtest_set_inside_write (0);
	lsrtest_set_nwritten (0);
	lsrtest_set_nwritten_total (0);

	p = malloc (10);
	if (p != NULL)
	{
		free(p);
	}
	else
	{
		fail("test_malloc: memory not allocated: errno=%d\n", errno);
	}
}
END_TEST
#endif /* HAVE_MALLOC */

START_TEST(test_valloc)
{
	void * p;

	lsrtest_set_inside_write (1);
	printf("test_valloc\n");
	lsrtest_set_inside_write (0);
	lsrtest_set_nwritten (0);
	lsrtest_set_nwritten_total (0);

	p = valloc (10);
	if (p == NULL)
	{
		fail("test_valloc: memory not allocated: errno=%d\n", errno);
	}
	/* pointer returned by valloc is not officially safe to be used with free(p) */
}
END_TEST

START_TEST(test_pvalloc)
{
	void * p;

	lsrtest_set_inside_write (1);
	printf("test_pvalloc\n");
	lsrtest_set_inside_write (0);
	lsrtest_set_nwritten (0);
	lsrtest_set_nwritten_total (0);

	p = pvalloc (10);
	if (p == NULL)
	{
		fail("test_pvalloc: memory not allocated: errno=%d\n", errno);
	}
	/* pointer returned by pvalloc is not officially safe to be used with free(p) */
}
END_TEST

#ifdef HAVE_SBRK
START_TEST(test_sbrk)
{
	void * p;

	lsrtest_set_inside_write (1);
	printf("test_sbrk\n");
	lsrtest_set_inside_write (0);
	lsrtest_set_nwritten (0);
	lsrtest_set_nwritten_total (0);

	p = sbrk (10);
	if (p == (void *) -1)
	{
		fail("test_sbrk: memory not allocated: errno=%d\n", errno);
	}
}
END_TEST
#endif

#ifdef HAVE_BRK
START_TEST(test_brk)
{
	int r;

	lsrtest_set_inside_write (1);
	printf("test_brk\n");
	lsrtest_set_inside_write (0);
	lsrtest_set_nwritten (0);
	lsrtest_set_nwritten_total (0);

	r = brk ((char *)sbrk(0)+10);
	if (r == -1)
	{
		fail("test_brk: memory not allocated: errno=%d\n", errno);
	}
}
END_TEST
#endif

#ifdef HAVE_MEMALIGN
START_TEST(test_memalign)
{
	void * p;

	lsrtest_set_inside_write (1);
	printf("test_memalign\n");
	lsrtest_set_inside_write (0);
	lsrtest_set_nwritten (0);
	lsrtest_set_nwritten_total (0);

	p = memalign (8, 10);
	if (p == NULL)
	{
		fail("test_memalign: memory not allocated: errno=%d\n", errno);
	}
	/* pointer returned by memalign is not officially safe to be used with free(p) */
}
END_TEST
#endif

#ifdef HAVE_ALIGNED_ALLOC
START_TEST(test_aligned_alloc)
{
	void * p;

	lsrtest_set_inside_write (1);
	printf("test_aligned_alloc\n");
	lsrtest_set_inside_write (0);
	lsrtest_set_nwritten (0);
	lsrtest_set_nwritten_total (0);

	p = aligned_alloc (8, 10);
	if (p == NULL)
	{
		fail("test_aligned_alloc: memory not allocated: errno=%d\n", errno);
	}
	/* pointer returned by aligned_alloc is not officially safe to be used with free(p) */
}
END_TEST
#endif

#ifdef HAVE_POSIX_MEMALIGN
START_TEST(test_posix_memalign)
{
	void * p = NULL;
	int r;

	lsrtest_set_inside_write (1);
	printf("test_posix_memalign\n");
	lsrtest_set_inside_write (0);
	lsrtest_set_nwritten (0);
	lsrtest_set_nwritten_total (0);

	r = posix_memalign (&p, 8, 10);
	if (p != NULL)
	{
		free(p);
	}
	else
	{
		fail("test_posix_memalign: memory not allocated: errno=%d\n", errno);
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
