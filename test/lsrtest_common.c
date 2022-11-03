/*
 * LibSecRm - A library for secure removing files.
 *	-- unit test common functions.
 *
 * Copyright (C) 2015-2022 Bogdan Drozdowski, bogdro (at) users . sourceforge . net
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

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#include <stdio.h>

#ifdef HAVE_STRING_H
# if (!defined STDC_HEADERS) && (defined HAVE_MEMORY_H)
#  include <memory.h>
# endif
# include <string.h>
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#else
# define O_RDONLY	0
# define O_WRONLY	1
# define O_RDWR		2
# define O_TRUNC	01000
#endif

static def_write orig_write;
static volatile size_t nwritten = 0;
static volatile size_t nwritten_total = 0;
static volatile long was_in_write_flag = 0;
static volatile int is_inside_write_flag = 0;
#ifdef LSR_CAN_USE_PIPE
static int pipe_desc = -1;
#endif

ssize_t write(int fd, const void *buf, size_t count)
{
	ssize_t res;
	if (is_inside_write_flag == 0)
	{
		is_inside_write_flag = 1;
		was_in_write_flag += 1;
		nwritten = count;
		nwritten_total += count;
		/*fprintf(stderr, "write of %d bytes to fd=%d\n", count, fd);
		fflush(stderr);*/
		res = (*orig_write)(fd, buf, count);
		is_inside_write_flag = 0;
		return res;
	}
	else
	{
		return (*orig_write)(fd, buf, count);
	}
}

static def_rename orig_rename;
static char last_name[50];

int rename(const char *oldpath, const char *newpath)
{
	strncpy(last_name, newpath, sizeof(last_name)-1);
	last_name[sizeof(last_name)-1] = '\0';
	return (*orig_rename)(oldpath, newpath);
}

size_t lsrtest_get_nwritten (void)
{
	return nwritten;
}

size_t lsrtest_get_nwritten_total (void)
{
	return nwritten_total;
}

void lsrtest_set_nwritten (size_t s)
{
	nwritten = s;
}

void lsrtest_set_nwritten_total (size_t s)
{
	nwritten_total = s;
}

long int lsrtest_was_in_write (void)
{
	return was_in_write_flag;
}

int lsrtest_is_inside_write (void)
{
	return is_inside_write_flag;
}

void lsrtest_set_inside_write (int v)
{
	is_inside_write_flag = v;
}

const char * lsrtest_get_last_name (void)
{
	return last_name;
}

void lsrtest_set_last_name (const char newpath[])
{
	strncpy(last_name, newpath, sizeof(last_name)-1);
	last_name[sizeof(last_name)-1] = '\0';
}

/* ======================================================= */

void lsrtest_prepare_banned_file(void)
{
	FILE *f = NULL;
	f = fopen(LSR_TEST_BANNED_FILENAME, "w");
	if (f != NULL)
	{
		fwrite("aaa", 1, LSR_TEST_FILE_LENGTH, f);
		fclose(f);
	}
}

/* ======================================================= */

#ifdef LSR_CAN_USE_PIPE
void lsrtest_prepare_pipe(void)
{
	mkfifo (LSR_PIPE_FILENAME, 0666);
}
#endif /* LSR_CAN_USE_PIPE */

/* ======================================================= */

/* it's crucial that the orig_write() is created before anything else runs */
__attribute__ ((constructor))
static void setup_global(void) /* unchecked */
{
	*(void **) (&orig_write) = dlsym (RTLD_NEXT, "write");
	*(void **) (&orig_rename) = dlsym (RTLD_NEXT, "rename");
}

/*
static void teardown_global(void)
{
}
*/

static void setup_test(void) /* checked */
{
	FILE *f = NULL;
	f = fopen(LSR_TEST_FILENAME, "w");
	if (f != NULL)
	{
		fwrite("aaa", 1, LSR_TEST_FILE_LENGTH, f);
		fclose(f);
	}
#ifdef LSR_CAN_USE_PIPE
	/* need to open to allow writing */
	pipe_desc = open (LSR_PIPE_FILENAME, O_RDONLY);
#endif
}

static void teardown_test(void)
{
	unlink(LSR_TEST_FILENAME);
	unlink(LSR_TEST_BANNED_FILENAME);
#ifdef LSR_CAN_USE_PIPE
	if ( pipe_desc >= 0 )
	{
		close (pipe_desc);
	}
	unlink(LSR_PIPE_FILENAME);
#endif
}

TCase * lsrtest_add_fixtures(TCase * tests)
{
	if ( tests != NULL )
	{
		tcase_add_checked_fixture(tests, &setup_test, &teardown_test);
		/*tcase_add_unchecked_fixture(tests, &setup_global, &teardown_global);*/
	}
	return tests;
}
