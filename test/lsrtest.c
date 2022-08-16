/*
 * A library for secure removing files.
 *	-- unit test.
 *
 * Copyright (C) 2015-2017 Bogdan Drozdowski, bogdandr (at) op.pl
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
#define __USE_GNU

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

#include <libsecrm.h>
#include <check.h>

/* compatibility with older check versions */
#ifndef ck_abort
# define ck_abort() ck_abort_msg(NULL)
# define ck_abort_msg fail
# define ck_assert(C) ck_assert_msg(C, NULL)
# define ck_assert_msg fail_unless
#endif

#ifndef _ck_assert_int
# define _ck_assert_int(X, O, Y) ck_assert_msg((X) O (Y), "Assertion '"#X#O#Y"' failed: "#X"==%d, "#Y"==%d", X, Y)
# define ck_assert_int_eq(X, Y) _ck_assert_int(X, ==, Y)
# define ck_assert_int_ne(X, Y) _ck_assert_int(X, !=, Y)
#endif

#ifndef _ck_assert_str
# define _ck_assert_str(C, X, O, Y) ck_assert_msg(C, "Assertion '"#X#O#Y"' failed: "#X"==\"%s\", "#Y"==\"%s\"", X, Y)
# define ck_assert_str_eq(X, Y) _ck_assert_str(!strcmp(X, Y), X, ==, Y)
# define ck_assert_str_ne(X, Y) _ck_assert_str(strcmp(X, Y), X, !=, Y)
#endif


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

typedef ssize_t (*def_write)(int fd, const void *buf, size_t count);
static def_write orig_write;
static size_t nwritten = 0;

ssize_t write(int fd, const void *buf, size_t count)
{
	nwritten = count;
	return (*orig_write)(fd, buf, count);
}

typedef int (*def_rename)(const char *oldpath, const char *newpath);
static def_rename orig_rename;
static char last_name[20];

int rename(const char *oldpath, const char *newpath)
{
	strncpy(last_name, newpath, sizeof(last_name)-1);
	last_name[sizeof(last_name)-1] = '\0';
	return (*orig_rename)(oldpath, newpath);
}

#define LSR_TEST_FILENAME "zz1"
#define LSR_TEST_FILE_LENGTH 3
#define LSR_TEST_FILE_EXT_LENGTH 100
#define LSR_LINK_FILENAME "zzl"
#define LSR_TEST_BANNED_FILENAME "sh-thd-12345"
#define LSR_TEST_DIRNAME "zz1dir"

#if (defined LSR_ENABLE_USERBANS) && (defined HAVE_GETENV) \
	&& (defined HAVE_STDLIB_H) && (defined HAVE_MALLOC)
# define LSR_CAN_USE_BANS 1
#else
# undef LSR_CAN_USE_BANS
#endif

#if (defined LSR_ENABLE_ENV) && (defined HAVE_STDLIB_H) && (defined HAVE_GETENV)
# define LSR_CAN_USE_ENV 1
#else
# undef LSR_CAN_USE_ENV
#endif

/* ======================================================= */

static void prepare_banned_file(void);

static void prepare_banned_file(void)
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

#ifdef HAVE_OPENAT
START_TEST(test_openat_rdonly)
{
	int fd;

	printf("test_openat_rdonly\n");
	nwritten = 0;
	fd = openat(AT_FDCWD, LSR_TEST_FILENAME, O_RDONLY);
	if (fd >= 0)
	{
		close(fd);
	}
	else
	{
		fail("test_openat_rdonly: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq(nwritten, 0);
}
END_TEST

START_TEST(test_openat_rdwr)
{
	int fd;

	printf("test_openat_rdwr\n");
	nwritten = 0;
	fd = openat(AT_FDCWD, LSR_TEST_FILENAME, O_RDWR);
	if (fd >= 0)
	{
		close(fd);
	}
	else
	{
		fail("test_openat_rdwr: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq(nwritten, 0);
}
END_TEST

START_TEST(test_openat_wronly)
{
	int fd;

	printf("test_openat_wronly\n");
	nwritten = 0;
	fd = openat(AT_FDCWD, LSR_TEST_FILENAME, O_WRONLY);
	if (fd >= 0)
	{
		close(fd);
	}
	else
	{
		fail("test_openat_wronly: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq(nwritten, 0);
}
END_TEST

START_TEST(test_openat_trunc)
{
	int fd;

	printf("test_openat_trunc\n");
	nwritten = 0;
	fd = openat(AT_FDCWD, LSR_TEST_FILENAME, O_WRONLY | O_TRUNC);
	if (fd >= 0)
	{
		close(fd);
	}
	else
	{
		fail("test_openat_trunc: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq(nwritten, LSR_TEST_FILE_LENGTH);
}
END_TEST

START_TEST(test_openat_trunc_banned)
{
	int fd;

	printf("test_openat_trunc_banned\n");
	prepare_banned_file();
	nwritten = 0;
	fd = openat(AT_FDCWD, LSR_TEST_BANNED_FILENAME, O_WRONLY | O_TRUNC);
	if (fd >= 0)
	{
		close(fd);
	}
	else
	{
		fail("test_openat_trunc_banned: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq(nwritten, 0);
}
END_TEST
#endif /* HAVE_OPENAT */

START_TEST(test_unlink_file)
{
	int r;
#if (defined HAVE_SYS_STAT_H) && (defined HAVE_ERRNO_H)
	struct stat s;
#endif

	printf("test_unlink_file\n");
	nwritten = 0;
	strcpy (last_name, LSR_TEST_FILENAME);
	r = unlink (LSR_TEST_FILENAME);
	if (r != 0)
	{
		fail("test_unlink_file: file could not be deleted: errno=%d, r=%d\n", errno, r);
	}
#if (defined HAVE_SYS_STAT_H) && (defined HAVE_ERRNO_H)
	r = stat (LSR_TEST_FILENAME, &s);
	if ( (r != -1) || (errno != ENOENT) )
	{
		fail("test_unlink_file: file still exists after delete: errno=%d, r=%d\n", errno, r);
	}
	r = stat (last_name, &s);
	if ( (r != -1) || (errno != ENOENT) )
	{
		fail("test_unlink_file: renamed file still exists after delete: errno=%d, r=%d\n", errno, r);
	}
#endif
	if ( strcmp (LSR_TEST_FILENAME, last_name) == 0 )
	{
		fail("test_unlink_file: new filename equal to the old one\n");
	}
	ck_assert_int_eq(nwritten, LSR_TEST_FILE_LENGTH);
}
END_TEST

#ifdef HAVE_SYMLINK
START_TEST(test_unlink_link)
{
	int r;
# if (defined HAVE_SYS_STAT_H) && (defined HAVE_ERRNO_H)
	struct stat s;
# endif

	printf("test_unlink_link\n");
	r = symlink (LSR_TEST_FILENAME, LSR_LINK_FILENAME);
	if (r != 0)
	{
		fail("test_unlink_link: link could not be created: errno=%d, r=%d\n", errno, r);
	}
	nwritten = 0;
	strcpy (last_name, LSR_LINK_FILENAME);
	r = unlink (LSR_LINK_FILENAME);
	if (r != 0)
	{
		fail("test_unlink_link: link could not be deleted: errno=%d, r=%d\n", errno, r);
	}
# if (defined HAVE_SYS_STAT_H) && (defined HAVE_ERRNO_H)
	r = stat (LSR_LINK_FILENAME, &s);
	if ( (r != -1) || (errno != ENOENT) )
	{
		fail("test_unlink_link: link still exists after delete: errno=%d, r=%d\n", errno, r);
	}
	r = stat (last_name, &s);
	if ( (r != -1) || (errno != ENOENT) )
	{
		fail("test_unlink_link: renamed file still exists after delete: errno=%d, r=%d\n", errno, r);
	}
# endif
	/* unlink() skips non-files, so the name shouldn't be changed */
	if ( strcmp (LSR_LINK_FILENAME, last_name) != 0 )
	{
		fail("test_unlink_link: new filename not equal to the old one\n");
	}
	ck_assert_int_eq(nwritten, 0);
}
END_TEST
#endif /* HAVE_SYMLINK */

#ifdef HAVE_UNLINKAT
START_TEST(test_unlinkat_file)
{
	int r;
# if (defined HAVE_SYS_STAT_H) && (defined HAVE_ERRNO_H)
	struct stat s;
# endif

	printf("test_unlinkat_file\n");
	nwritten = 0;
	strcpy (last_name, LSR_TEST_FILENAME);
	r = unlinkat (AT_FDCWD, LSR_TEST_FILENAME, 0);
	if (r != 0)
	{
		fail("test_unlinkat_file: file could not be deleted: errno=%d, r=%d\n", errno, r);
	}
# if (defined HAVE_SYS_STAT_H) && (defined HAVE_ERRNO_H)
	r = stat (LSR_TEST_FILENAME, &s);
	if ( (r != -1) || (errno != ENOENT) )
	{
		fail("test_unlinkat_file: file still exists after delete: errno=%d, r=%d\n", errno, r);
	}
	r = stat (last_name, &s);
	if ( (r != -1) || (errno != ENOENT) )
	{
		fail("test_unlinkat_file: renamed file still exists after delete: errno=%d, r=%d\n", errno, r);
	}
# endif
	if ( strcmp (LSR_TEST_FILENAME, last_name) == 0 )
	{
		fail("test_unlinkat_file: new filename equal to the old one\n");
	}
	ck_assert_int_eq(nwritten, LSR_TEST_FILE_LENGTH);
}
END_TEST

START_TEST(test_unlinkat_file_banned)
{
	int r;
# if (defined HAVE_SYS_STAT_H) && (defined HAVE_ERRNO_H)
	struct stat s;
# endif

	printf("test_unlinkat_file_banned\n");
	prepare_banned_file();
	nwritten = 0;
	strcpy (last_name, LSR_TEST_BANNED_FILENAME);
	r = unlinkat (AT_FDCWD, LSR_TEST_BANNED_FILENAME, 0);
	if (r != 0)
	{
		fail("test_unlinkat_file_banned: file could not be deleted: errno=%d, r=%d\n", errno, r);
	}
# if (defined HAVE_SYS_STAT_H) && (defined HAVE_ERRNO_H)
	r = stat (LSR_TEST_BANNED_FILENAME, &s);
	if ( (r != -1) || (errno != ENOENT) )
	{
		fail("test_unlinkat_file_banned: file still exists after delete: errno=%d, r=%d\n", errno, r);
	}
	r = stat (last_name, &s);
	if ( (r != -1) || (errno != ENOENT) )
	{
		fail("test_unlinkat_file_banned: renamed file still exists after delete: errno=%d, r=%d\n", errno, r);
	}
# endif
	if ( strcmp (LSR_TEST_BANNED_FILENAME, last_name) != 0 )
	{
		fail("test_unlinkat_file_banned: banned file has been renamed, but shouldn't have been: new_name='%s'\n",
			last_name);
	}
	ck_assert_int_eq(nwritten, 0);
}
END_TEST
#endif /* HAVE_UNLINKAT */

START_TEST(test_remove)
{
	int r;
#if (defined HAVE_SYS_STAT_H) && (defined HAVE_ERRNO_H)
	struct stat s;
#endif

	printf("test_remove\n");
	nwritten = 0;
	strcpy (last_name, LSR_TEST_FILENAME);
	r = remove (LSR_TEST_FILENAME);
	if (r != 0)
	{
		fail("test_remove: file could not be deleted: errno=%d, r=%d\n", errno, r);
	}
#if (defined HAVE_SYS_STAT_H) && (defined HAVE_ERRNO_H)
	r = stat (LSR_TEST_FILENAME, &s);
	if ( (r != -1) || (errno != ENOENT) )
	{
		fail("test_remove: file still exists after delete: errno=%d, r=%d\n", errno, r);
	}
	r = stat (last_name, &s);
	if ( (r != -1) || (errno != ENOENT) )
	{
		fail("test_remove: renamed file still exists after delete: errno=%d, r=%d\n", errno, r);
	}
#endif
	if ( strcmp (LSR_TEST_FILENAME, last_name) == 0 )
	{
		fail("test_remove: new filename equal to the old one\n");
	}
	ck_assert_int_eq(nwritten, LSR_TEST_FILE_LENGTH);
}
END_TEST

START_TEST(test_remove_banned)
{
	int r;
#if (defined HAVE_SYS_STAT_H) && (defined HAVE_ERRNO_H)
	struct stat s;
#endif

	printf("test_remove_banned\n");
	prepare_banned_file();
	nwritten = 0;
	strcpy (last_name, LSR_TEST_BANNED_FILENAME);
	r = remove (LSR_TEST_BANNED_FILENAME);
	if (r != 0)
	{
		fail("test_remove_banned: file could not be deleted: errno=%d, r=%d\n", errno, r);
	}
#if (defined HAVE_SYS_STAT_H) && (defined HAVE_ERRNO_H)
	r = stat (LSR_TEST_BANNED_FILENAME, &s);
	if ( (r != -1) || (errno != ENOENT) )
	{
		fail("test_remove_banned: file still exists after delete: errno=%d, r=%d\n", errno, r);
	}
	r = stat (last_name, &s);
	if ( (r != -1) || (errno != ENOENT) )
	{
		fail("test_remove_banned: renamed file still exists after delete: errno=%d, r=%d\n", errno, r);
	}
#endif
	if ( strcmp (LSR_TEST_BANNED_FILENAME, last_name) != 0 )
	{
		fail("test_remove_banned: banned file has been renamed, but shouldn't have been: new_name='%s'\n",
			last_name);
	}
	ck_assert_int_eq(nwritten, 0);
}
END_TEST

#ifdef HAVE_MKDIR
START_TEST(test_rmdir)
{
	int r;
# if (defined HAVE_SYS_STAT_H) && (defined HAVE_ERRNO_H)
	struct stat s;
# endif

	printf("test_rmdir\n");
	r = mkdir (LSR_TEST_DIRNAME, S_IRUSR|S_IWUSR);
	if (r != 0)
	{
		fail("test_rmdir: directory could not be created: errno=%d, r=%d\n", errno, r);
	}
	nwritten = 0;
	strcpy (last_name, LSR_TEST_DIRNAME);
	r = rmdir (LSR_TEST_DIRNAME);
	if (r != 0)
	{
		fail("test_rmdir: directory could not be deleted: errno=%d, r=%d\n", errno, r);
	}
# if (defined HAVE_SYS_STAT_H) && (defined HAVE_ERRNO_H)
	r = stat (LSR_TEST_DIRNAME, &s);
	if ( (r != -1) || (errno != ENOENT) )
	{
		fail("test_rmdir: directory still exists after delete: errno=%d, r=%d\n", errno, r);
	}
	r = stat (last_name, &s);
	if ( (r != -1) || (errno != ENOENT) )
	{
		fail("test_rmdir: renamed directory still exists after delete: errno=%d, r=%d\n", errno, r);
	}
# endif
	if ( strcmp (LSR_TEST_DIRNAME, last_name) == 0 )
	{
		fail("test_rmdir: new directory name equal to the old one\n");
	}
	ck_assert_int_eq(nwritten, 0);
}
END_TEST
#endif /* HAVE_MKDIR */

START_TEST(test_ftruncate)
{
	int fd;
	int r;

	printf("test_ftruncate\n");
	nwritten = 0;
	fd = open(LSR_TEST_FILENAME, O_RDWR);
	if (fd >= 0)
	{
		r = ftruncate(fd, 0);
		if (r != 0)
		{
			fail("test_ftruncate: file could not be truncated: errno=%d, r=%d\n", errno, r);
		}
		close(fd);
	}
	else
	{
		fail("test_ftruncate: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq(nwritten, LSR_TEST_FILE_LENGTH);
}
END_TEST

START_TEST(test_truncate)
{
	int r;

	printf("test_truncate\n");
	nwritten = 0;
	r = truncate(LSR_TEST_FILENAME, 0);
	if (r != 0)
	{
		fail("test_truncate: file could not be truncated: errno=%d, r=%d\n", errno, r);
	}
	ck_assert_int_eq(nwritten, LSR_TEST_FILE_LENGTH);
}
END_TEST

START_TEST(test_truncate_banned)
{
	int r;

	printf("test_truncate_banned\n");
	prepare_banned_file();

	nwritten = 0;
	r = truncate(LSR_TEST_BANNED_FILENAME, 0);
	if (r != 0)
	{
		fail("test_truncate_banned: file could not be truncated: errno=%d, r=%d\n", errno, r);
	}
	ck_assert_int_eq(nwritten, 0);
}
END_TEST

START_TEST(test_fopen_r)
{
	FILE * f;

	printf("test_fopen_r\n");
	nwritten = 0;
	f = fopen(LSR_TEST_FILENAME, "r");
	if (f != NULL)
	{
		fclose(f);
	}
	else
	{
		fail("test_fopen_r: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq(nwritten, 0);
}
END_TEST

START_TEST(test_fopen_w)
{
	FILE * f;

	printf("test_fopen_w\n");
	nwritten = 0;
	f = fopen(LSR_TEST_FILENAME, "w");
	if (f != NULL)
	{
		fclose(f);
	}
	else
	{
		fail("test_fopen_w: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq(nwritten, LSR_TEST_FILE_LENGTH);
}
END_TEST

START_TEST(test_fopen_w_banned)
{
	FILE * f;

	printf("test_fopen_w_banned\n");
	prepare_banned_file();
	nwritten = 0;
	f = fopen(LSR_TEST_BANNED_FILENAME, "w");
	if (f != NULL)
	{
		fclose(f);
	}
	else
	{
		fail("test_fopen_w_banned: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq(nwritten, 0);
}
END_TEST

START_TEST(test_freopen_rr)
{
	FILE * f;

	printf("test_freopen_rr\n");
	nwritten = 0;
	f = fopen(LSR_TEST_FILENAME, "r");
	if (f != NULL)
	{
		ck_assert_int_eq(nwritten, 0);
		nwritten = 0;
		f = freopen(LSR_TEST_FILENAME, "r", f);
		if (f != NULL)
		{
			fclose(f);
		}
		else
		{
			fail("test_freopen_rr: file not re-opened: errno=%d\n", errno);
		}
	}
	else
	{
		fail("test_freopen_rr: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq(nwritten, 0);
}
END_TEST

START_TEST(test_freopen_rw)
{
	FILE * f;

	printf("test_freopen_rw\n");
	nwritten = 0;
	f = fopen(LSR_TEST_FILENAME, "r");
	if (f != NULL)
	{
		ck_assert_int_eq(nwritten, 0);
		nwritten = 0;
		f = freopen(LSR_TEST_FILENAME, "w", f);
		if (f != NULL)
		{
			fclose(f);
		}
		else
		{
			fail("test_freopen_rw: file not re-opened: errno=%d\n", errno);
		}
	}
	else
	{
		fail("test_freopen_rw: file not opened: errno=%d\n", errno);
	}
	/* file already opened and re-opened won't be wiped - fcntl()
	won't allow setting the exclusive lock */
	ck_assert_int_eq(nwritten, 0);
}
END_TEST

START_TEST(test_freopen_rw_banned)
{
	FILE * f;

	printf("test_freopen_rw_banned\n");
	prepare_banned_file();
	nwritten = 0;
	f = fopen(LSR_TEST_FILENAME, "r");
	if (f != NULL)
	{
		ck_assert_int_eq(nwritten, 0);
		nwritten = 0;
		f = freopen(LSR_TEST_BANNED_FILENAME, "w", f);
		if (f != NULL)
		{
			fclose(f);
		}
		else
		{
			fail("test_freopen_rw_banned: file not re-opened: errno=%d\n", errno);
		}
	}
	else
	{
		fail("test_freopen_rw_banned: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq(nwritten, 0);
}
END_TEST


START_TEST(test_freopen_rw_stdout)
{
	FILE * f;

	printf("test_freopen_rw_stdout\n");
	nwritten = 0;
	f = freopen(LSR_TEST_FILENAME, "w", stdout);
	if (f != NULL)
	{
		fclose(f);
	}
	else
	{
		fail("test_freopen_rw_stdout: file not re-opened: errno=%d\n", errno);
	}
	ck_assert_int_eq(nwritten, LSR_TEST_FILE_LENGTH);
}
END_TEST

START_TEST(test_freopen_rw_stdout_banned)
{
	FILE * f;

	printf("test_freopen_rw_stdout_banned\n");
	prepare_banned_file();
	nwritten = 0;
	f = freopen(LSR_TEST_BANNED_FILENAME, "w", stdout);
	if (f != NULL)
	{
		fclose(f);
	}
	else
	{
		fail("test_freopen_rw_stdout_banned: file not re-opened: errno=%d\n", errno);
	}
	ck_assert_int_eq(nwritten, 0);
}
END_TEST

START_TEST(test_freopen_wr)
{
	FILE * f;

	printf("test_freopen_wr\n");
	nwritten = 0;
	f = fopen(LSR_TEST_FILENAME, "w");
	if (f != NULL)
	{
		ck_assert_int_eq(nwritten, LSR_TEST_FILE_LENGTH);
		nwritten = 0;
		f = freopen(LSR_TEST_FILENAME, "r", f);
		if (f != NULL)
		{
			fclose(f);
		}
		else
		{
			fail("test_freopen_wr: file not re-opened: errno=%d\n", errno);
		}
	}
	else
	{
		fail("test_freopen_wr: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq(nwritten, 0);
}
END_TEST

START_TEST(test_freopen_ww)
{
	FILE * f;

	printf("test_freopen_ww\n");
	nwritten = 0;
	f = fopen(LSR_TEST_FILENAME, "w");
	if (f != NULL)
	{
		ck_assert_int_eq(nwritten, LSR_TEST_FILE_LENGTH);
		nwritten = 0;
		f = freopen(LSR_TEST_FILENAME, "w", f);
		if (f != NULL)
		{
			fclose(f);
		}
		else
		{
			fail("test_freopen_ww: file not re-opened: errno=%d\n", errno);
		}
	}
	else
	{
		fail("test_freopen_ww: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq(nwritten, 0);
}
END_TEST

START_TEST(test_freopen_ww_banned1)
{
	FILE * f;

	printf("test_freopen_ww_banned1\n");
	prepare_banned_file();
	nwritten = 0;
	f = fopen(LSR_TEST_BANNED_FILENAME, "w");
	if (f != NULL)
	{
		ck_assert_int_eq(nwritten, 0);
		nwritten = 0;
		f = freopen(LSR_TEST_FILENAME, "w", f);
		if (f != NULL)
		{
			fclose(f);
		}
		else
		{
			fail("test_freopen_ww_banned1: file not re-opened: errno=%d\n", errno);
		}
	}
	else
	{
		fail("test_freopen_ww_banned1: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq(nwritten, LSR_TEST_FILE_LENGTH);
}
END_TEST

START_TEST(test_freopen_ww_banned2)
{
	FILE * f;

	printf("test_freopen_ww_banned2\n");
	prepare_banned_file();
	nwritten = 0;
	f = fopen(LSR_TEST_FILENAME, "w");
	if (f != NULL)
	{
		ck_assert_int_eq(nwritten, LSR_TEST_FILE_LENGTH);
		nwritten = 0;
		f = freopen(LSR_TEST_BANNED_FILENAME, "w", f);
		if (f != NULL)
		{
			fclose(f);
		}
		else
		{
			fail("test_freopen_ww_banned2: file not re-opened: errno=%d\n", errno);
		}
	}
	else
	{
		fail("test_freopen_ww_banned2: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq(nwritten, 0);
}
END_TEST

START_TEST(test_open_rdwr)
{
	int fd;

	printf("test_open_rdwr\n");
	nwritten = 0;
	fd = open(LSR_TEST_FILENAME, O_RDWR);
	if (fd >= 0)
	{
		close(fd);
	}
	else
	{
		fail("test_open_rdwr: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq(nwritten, 0);
}
END_TEST

START_TEST(test_open_wronly)
{
	int fd;

	printf("test_open_wronly\n");
	nwritten = 0;
	fd = open(LSR_TEST_FILENAME, O_WRONLY);
	if (fd >= 0)
	{
		close(fd);
	}
	else
	{
		fail("test_open_wronly: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq(nwritten, 0);
}
END_TEST

START_TEST(test_open_rdonly)
{
	int fd;

	printf("test_open_rdonly\n");
	nwritten = 0;
	fd = open(LSR_TEST_FILENAME, O_RDONLY);
	if (fd >= 0)
	{
		close(fd);
	}
	else
	{
		fail("test_open_rdonly: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq(nwritten, 0);
}
END_TEST

START_TEST(test_open_proc)
{
	int fd;

	printf("test_open_proc\n");
	nwritten = 0;
	fd = open("/proc/cpuinfo", O_RDONLY);
	if (fd >= 0)
	{
		close(fd);
	}
	else
	{
		fail("test_open_proc: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq(nwritten, 0);
}
END_TEST

START_TEST(test_open_trunc)
{
	int fd;

	printf("test_open_trunc\n");
	nwritten = 0;
	fd = open(LSR_TEST_FILENAME, O_WRONLY | O_TRUNC);
	if (fd >= 0)
	{
		close(fd);
	}
	else
	{
		fail("test_open_trunc: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq(nwritten, LSR_TEST_FILE_LENGTH);
}
END_TEST

START_TEST(test_open_trunc_banned)
{
	int fd;

	printf("test_open_trunc_banned\n");
	prepare_banned_file();
	nwritten = 0;
	fd = open(LSR_TEST_BANNED_FILENAME, O_WRONLY | O_TRUNC);
	if (fd >= 0)
	{
		close(fd);
	}
	else
	{
		fail("test_open_trunc_banned: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq(nwritten, 0);
}
END_TEST

START_TEST(test_creat)
{
	int fd;

	printf("test_creat\n");
	nwritten = 0;
	fd = creat(LSR_TEST_FILENAME, S_IRUSR|S_IWUSR);
	if (fd >= 0)
	{
		close(fd);
	}
	else
	{
		fail("test_creat: file not created: errno=%d\n", errno);
	}
	ck_assert_int_eq(nwritten, LSR_TEST_FILE_LENGTH);
}
END_TEST

START_TEST(test_fdopen_r)
{
	int fd;
	FILE * f;

	printf("test_fdopen_r\n");
	nwritten = 0;
	fd = open(LSR_TEST_FILENAME, O_RDONLY);
	if (fd >= 0)
	{
		ck_assert_int_eq(nwritten, 0);
		nwritten = 0;
		f = fdopen(fd, "r");
		if (f != NULL)
		{
			fclose(f);
		}
		else
		{
			fail("test_fdopen_r: file not re-opened: errno=%d\n", errno);
		}
	}
	else
	{
		fail("test_fdopen_r: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq(nwritten, 0);
}
END_TEST

START_TEST(test_fdopen_w)
{
	int fd;
	FILE * f;

	printf("test_fdopen_w\n");
	nwritten = 0;
	fd = open(LSR_TEST_FILENAME, O_RDWR);
	if (fd >= 0)
	{
		ck_assert_int_eq(nwritten, 0);
		nwritten = 0;
		f = fdopen(fd, "w");
		if (f != NULL)
		{
			fclose(f);
		}
		else
		{
			fail("test_fdopen_w: file not re-opened: errno=%d\n", errno);
		}
	}
	else
	{
		fail("test_fdopen_w: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq(nwritten, 0); /* fdopen(w) should not truncate */
}
END_TEST

/* ======================================================= */

START_TEST(test_unlink_banned)
{
	int r;
#if (defined HAVE_SYS_STAT_H) && (defined HAVE_ERRNO_H)
	struct stat s;
#endif

	printf("test_unlink_banned\n");
	prepare_banned_file();

	strcpy (last_name, LSR_TEST_BANNED_FILENAME);
	nwritten = 0;
	r = unlink (LSR_TEST_BANNED_FILENAME);
	if (r != 0)
	{
		fail("test_unlink_banned: file could not be deleted: errno=%d, r=%d\n", errno, r);
	}
#if (defined HAVE_SYS_STAT_H) && (defined HAVE_ERRNO_H)
	r = stat (LSR_TEST_BANNED_FILENAME, &s);
	if ( (r != -1) || (errno != ENOENT) )
	{
		fail("test_unlink_banned: file still exists after delete: errno=%d, r=%d\n", errno, r);
	}
#endif
	if ( strcmp (LSR_TEST_BANNED_FILENAME, last_name) != 0 )
	{
		fail("test_unlink_banned: banned file has been renamed, but shouldn't have been: new_name='%s'\n",
			last_name);
	}
	ck_assert_int_eq(nwritten, 0);
}
END_TEST

START_TEST(test_wipe_opened)
{
	int fd, fd1;

	printf("test_wipe_opened\n");
	nwritten = 0;
	fd1 = open(LSR_TEST_FILENAME, O_RDONLY);
	if (fd1 < 0)
	{
		fail("test_wipe_opened: file not opened: errno=%d\n", errno);
	}
	fd = open(LSR_TEST_FILENAME, O_WRONLY | O_TRUNC);
	if (fd >= 0)
	{
		close(fd);
		close(fd1);
	}
	else
	{
		close(fd1);
		fail("test_wipe_opened: file not opened: errno=%d\n", errno);
	}
	ck_assert_int_eq(nwritten, 0);
}
END_TEST

#ifdef LSR_CAN_USE_BANS
START_TEST(test_banned_in_userfile_prog)
{
	int fd;
	FILE * user_ban_file;
	char * user_ban_file_name;
	char * home_env;
	int err;
	long file_len;

	printf("test_banned_in_userfile_prog\n");

	home_env = getenv("HOME");
	user_ban_file_name = (char *) malloc (strlen (home_env) + 1
		+ strlen (LSR_PROG_BANNING_USERFILE) + 1);
	if ( user_ban_file_name == NULL )
	{
		fail("test_banned_in_userfile_prog: cannot allocate memory: errno=%d\n", errno);
	}
	strcpy (user_ban_file_name, home_env);
	strcat (user_ban_file_name, "/");
	strcat (user_ban_file_name, LSR_PROG_BANNING_USERFILE);

	user_ban_file = fopen (user_ban_file_name, "a+");
	if ( user_ban_file == NULL )
	{
		err = errno;
		free (user_ban_file_name);
		fail("test_banned_in_userfile_prog: cannot open user file: errno=%d\n", err);
	}

	fseek (user_ban_file, 0, SEEK_END);
	file_len = ftell (user_ban_file);
	fwrite ("\nlsrtest\n", 1, strlen("\nlsrtest\n"), user_ban_file);
	fclose (user_ban_file);

	nwritten = 0;
	fd = open(LSR_TEST_FILENAME, O_WRONLY | O_TRUNC);
	err = errno;
	if ( file_len == 0 )
	{
		unlink (user_ban_file_name);
	}
	else
	{
		truncate (user_ban_file_name, file_len);
	}
	if (fd >= 0)
	{
		close(fd);
	}
	else
	{
		free (user_ban_file_name);
		fail("test_banned_in_userfile_prog: file not opened: errno=%d\n", err);
	}
	free (user_ban_file_name);
	ck_assert_int_eq(nwritten, 0);
}
END_TEST

START_TEST(test_banned_in_userfile_file)
{
	int fd;
	FILE * user_ban_file;
	char * user_ban_file_name;
	char * home_env;
	int err;
	long file_len;

	printf("test_banned_in_userfile_file\n");

	home_env = getenv("HOME");
	user_ban_file_name = (char *) malloc (strlen (home_env) + 1
		+ strlen (LSR_FILE_BANNING_USERFILE) + 1);
	if ( user_ban_file_name == NULL )
	{
		fail("test_banned_in_userfile_file: cannot allocate memory: errno=%d\n", errno);
	}
	strcpy (user_ban_file_name, home_env);
	strcat (user_ban_file_name, "/");
	strcat (user_ban_file_name, LSR_FILE_BANNING_USERFILE);

	user_ban_file = fopen (user_ban_file_name, "a+");
	if ( user_ban_file == NULL )
	{
		err = errno;
		free (user_ban_file_name);
		fail("test_banned_in_userfile_file: cannot open user file: errno=%d\n", err);
	}

	fseek (user_ban_file, 0, SEEK_END);
	file_len = ftell (user_ban_file);
	fwrite ("\n" LSR_TEST_FILENAME "\n", 1,
		strlen("\n" LSR_TEST_FILENAME "\n"), user_ban_file);
	fclose (user_ban_file);

	nwritten = 0;
	fd = open(LSR_TEST_FILENAME, O_WRONLY | O_TRUNC);
	err = errno;
	if ( file_len == 0 )
	{
		unlink (user_ban_file_name);
	}
	else
	{
		truncate (user_ban_file_name, file_len);
	}
	if (fd >= 0)
	{
		close(fd);
	}
	else
	{
		free (user_ban_file_name);
		fail("test_banned_in_userfile_file: file not opened: errno=%d\n", err);
	}
	free (user_ban_file_name);
	ck_assert_int_eq(nwritten, 0);
}
END_TEST
#endif

#ifdef LSR_CAN_USE_ENV
START_TEST(test_banned_in_env_prog)
{
	int fd;
	FILE * env_ban_file;
	char env_ban_file_name[] = "libsecrm.env";
	int err;
	long file_len;
	int res;

	printf("test_banned_in_env_prog\n");

	res = setenv(LSR_PROG_BANNING_ENV, env_ban_file_name, 1);
	if ( res != 0 )
	{
		fail("test_banned_in_env_prog: cannot set environment: errno=%d\n", errno);
	}

	env_ban_file = fopen (env_ban_file_name, "a+");
	if ( env_ban_file == NULL )
	{
		fail("test_banned_in_env_prog: cannot open user file: errno=%d\n", errno);
	}

	fseek (env_ban_file, 0, SEEK_END);
	file_len = ftell (env_ban_file);
	fwrite ("\nlsrtest\n", 1, strlen("\nlsrtest\n"), env_ban_file);
	fclose (env_ban_file);

	nwritten = 0;
	fd = open(LSR_TEST_FILENAME, O_WRONLY | O_TRUNC);
	err = errno;
	if ( file_len == 0 )
	{
		unlink (env_ban_file_name);
	}
	else
	{
		truncate (env_ban_file_name, file_len);
	}
	if (fd >= 0)
	{
		close(fd);
	}
	else
	{
		fail("test_banned_in_env_prog: file not opened: errno=%d\n", err);
	}
	ck_assert_int_eq(nwritten, 0);
}
END_TEST

START_TEST(test_banned_in_env_file)
{
	int fd;
	FILE * env_ban_file;
	char env_ban_file_name[] = "libsecrm.env";
	int err;
	long file_len;
	int res;

	printf("test_banned_in_env_file\n");

	res = setenv(LSR_FILE_BANNING_ENV, env_ban_file_name, 1);
	if ( res != 0 )
	{
		fail("test_banned_in_env_prog: cannot set environment: errno=%d\n", errno);
	}

	env_ban_file = fopen (env_ban_file_name, "a+");
	if ( env_ban_file == NULL )
	{
		fail("test_banned_in_env_file: cannot open user file: errno=%d\n", errno);
	}

	fseek (env_ban_file, 0, SEEK_END);
	file_len = ftell (env_ban_file);
	fwrite ("\n" LSR_TEST_FILENAME "\n", 1,
		strlen("\n" LSR_TEST_FILENAME "\n"), env_ban_file);
	fclose (env_ban_file);

	nwritten = 0;
	fd = open(LSR_TEST_FILENAME, O_WRONLY | O_TRUNC);
	err = errno;
	if ( file_len == 0 )
	{
		unlink (env_ban_file_name);
	}
	else
	{
		truncate (env_ban_file_name, file_len);
	}
	if (fd >= 0)
	{
		close(fd);
	}
	else
	{
		fail("test_banned_in_env_file: file not opened: errno=%d\n", err);
	}
	ck_assert_int_eq(nwritten, 0);
}
END_TEST
#endif

/* ======================================================= */

#ifdef HAVE_MALLOC
START_TEST(test_malloc)
{
	void * p;

	printf("test_malloc\n");
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

	printf("test_valloc\n");
	p = valloc (10);
	if (p == NULL)
	{
		fail("test_valloc: memory not allocated: errno=%d\n", errno);
	}
	/* pointer returned by valloc is not safe to be used with free(p) */
}
END_TEST

START_TEST(test_pvalloc)
{
	void * p;

	printf("test_pvalloc\n");
	p = pvalloc (10);
	if (p == NULL)
	{
		fail("test_pvalloc: memory not allocated: errno=%d\n", errno);
	}
	/* pointer returned by pvalloc is not safe to be used with free(p) */
}
END_TEST

#ifdef HAVE_SBRK
START_TEST(test_sbrk)
{
	void * p;

	printf("test_sbrk\n");
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

	printf("test_brk\n");
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

	printf("test_memalign\n");
	p = memalign (8, 10);
	if (p == NULL)
	{
		fail("test_memalign: memory not allocated: errno=%d\n", errno);
	}
	/* pointer returned by memalign is not safe to be used with free(p) */
}
END_TEST
#endif

#ifdef HAVE_POSIX_MEMALIGN
START_TEST(test_posix_memalign)
{
	void * p;
	int r;

	printf("test_posix_memalign\n");
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

#ifdef HAVE_FALLOCATE
START_TEST(test_fallocate)
{
	int fd;
	int r;

	printf("test_fallocate\n");
	nwritten = 0;
	fd = open(LSR_TEST_FILENAME, O_RDWR);
	if (fd >= 0)
	{
		ck_assert_int_eq(nwritten, 0);
		nwritten = 0;
		r = fallocate(fd, 0, 0, LSR_TEST_FILE_EXT_LENGTH);
		close(fd);
		ck_assert_int_eq(nwritten, LSR_TEST_FILE_EXT_LENGTH - LSR_TEST_FILE_LENGTH);
		if (r != 0)
		{
			fail("test_fallocate: file not extended: errno=%d\n", errno);
		}
	}
	else
	{
		fail("test_fallocate: file not opened: errno=%d\n", errno);
	}
}
END_TEST
#endif

#ifdef HAVE_POSIX_FALLOCATE
START_TEST(test_posix_fallocate)
{
	int fd;
	int r;

	printf("test_posix_fallocate\n");
	nwritten = 0;
	fd = open(LSR_TEST_FILENAME, O_RDWR);
	if (fd >= 0)
	{
		ck_assert_int_eq(nwritten, 0);
		nwritten = 0;
		r = posix_fallocate(fd, 0, LSR_TEST_FILE_EXT_LENGTH);
		close(fd);
		ck_assert_int_eq(nwritten, LSR_TEST_FILE_EXT_LENGTH - LSR_TEST_FILE_LENGTH);
		if (r != 0)
		{
			fail("test_posix_fallocate: file not extended: errno=%d\n", errno);
		}
	}
	else
	{
		fail("test_posix_fallocate: file not opened: errno=%d\n", errno);
	}
}
END_TEST
#endif

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
}

static void teardown_test(void)
{
	unlink(LSR_TEST_FILENAME);
	unlink(LSR_TEST_BANNED_FILENAME);
}

static Suite * lsr_create_suite(void)
{
	Suite * s = suite_create("libsecrm");

	TCase * tests_open = tcase_create("open");
	TCase * tests_del = tcase_create("delete");
	TCase * tests_fopen = tcase_create("fopen");
	TCase * tests_mem = tcase_create("memory");
	TCase * tests_falloc_trunc = tcase_create("falloc_trunc");
	TCase * tests_banned = tcase_create("banning");

#ifdef HAVE_OPENAT
	tcase_add_test(tests_open, test_openat_rdonly);
	tcase_add_test(tests_open, test_openat_rdwr);
	tcase_add_test(tests_open, test_openat_wronly);
	tcase_add_test(tests_open, test_openat_trunc);
#endif
	tcase_add_test(tests_open, test_open_rdwr);
	tcase_add_test(tests_open, test_open_wronly);
	tcase_add_test(tests_open, test_open_rdonly);
	tcase_add_test(tests_open, test_open_proc);
	tcase_add_test(tests_open, test_open_trunc);
	tcase_add_test(tests_open, test_creat);

	tcase_add_test(tests_del, test_unlink_file);
#ifdef HAVE_UNLINKAT
	tcase_add_test(tests_del, test_unlinkat_file);
#endif
#ifdef HAVE_SYMLINK
	tcase_add_test(tests_del, test_unlink_link);
#endif
	tcase_add_test(tests_del, test_remove);
#ifdef HAVE_MKDIR
	tcase_add_test(tests_del, test_rmdir);
#endif

#ifdef HAVE_FALLOCATE
	tcase_add_test(tests_falloc_trunc, test_fallocate);
#endif
#ifdef HAVE_POSIX_FALLOCATE
	tcase_add_test(tests_falloc_trunc, test_posix_fallocate);
#endif
	tcase_add_test(tests_falloc_trunc, test_ftruncate);
	tcase_add_test(tests_falloc_trunc, test_truncate);

	tcase_add_test(tests_fopen, test_fopen_r);
	tcase_add_test(tests_fopen, test_fopen_w);
	tcase_add_test(tests_fopen, test_freopen_rr);
	tcase_add_test(tests_fopen, test_freopen_rw);
	tcase_add_test(tests_fopen, test_freopen_wr);
	tcase_add_test(tests_fopen, test_freopen_ww);
	tcase_add_test(tests_fopen, test_fdopen_r);
	tcase_add_test(tests_fopen, test_fdopen_w);

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
#ifdef HAVE_POSIX_MEMALIGN
	tcase_add_test(tests_mem, test_posix_memalign);
#endif

#ifdef HAVE_OPENAT
	tcase_add_test(tests_banned, test_openat_trunc_banned);
#endif
#ifdef HAVE_UNLINKAT
	tcase_add_test(tests_banned, test_unlinkat_file_banned);
#endif
	tcase_add_test(tests_banned, test_unlink_banned);
	tcase_add_test(tests_banned, test_remove_banned);
	tcase_add_test(tests_banned, test_wipe_opened);
	tcase_add_test(tests_banned, test_truncate_banned);
	tcase_add_test(tests_banned, test_fopen_w_banned);
	tcase_add_test(tests_banned, test_freopen_rw_banned);
	tcase_add_test(tests_banned, test_freopen_ww_banned1);
	tcase_add_test(tests_banned, test_freopen_ww_banned2);
	tcase_add_test(tests_banned, test_freopen_rw_stdout);
	tcase_add_test(tests_banned, test_freopen_rw_stdout_banned);
	tcase_add_test(tests_banned, test_open_trunc_banned);
#ifdef LSR_CAN_USE_BANS
	tcase_add_test(tests_banned, test_banned_in_userfile_prog);
	tcase_add_test(tests_banned, test_banned_in_userfile_file);
#endif
#ifdef LSR_CAN_USE_ENV
	tcase_add_test(tests_banned, test_banned_in_env_prog);
	tcase_add_test(tests_banned, test_banned_in_env_file);
#endif

	tcase_add_checked_fixture(tests_open, &setup_test, &teardown_test);
	tcase_add_checked_fixture(tests_del, &setup_test, &teardown_test);
	tcase_add_checked_fixture(tests_falloc_trunc, &setup_test, &teardown_test);
	tcase_add_checked_fixture(tests_fopen, &setup_test, &teardown_test);
	tcase_add_checked_fixture(tests_banned, &setup_test, &teardown_test);

	/*tcase_add_unchecked_fixture(tests, &setup_global, &teardown_global);*/

	/* set 30-second timeouts */
	tcase_set_timeout(tests_open, 30);
	tcase_set_timeout(tests_del, 30);
	tcase_set_timeout(tests_falloc_trunc, 30);
	tcase_set_timeout(tests_fopen, 30);
	tcase_set_timeout(tests_mem, 30);
	tcase_set_timeout(tests_banned, 30);

	suite_add_tcase(s, tests_open);
	suite_add_tcase(s, tests_del);
	suite_add_tcase(s, tests_falloc_trunc);
	suite_add_tcase(s, tests_fopen);
	suite_add_tcase(s, tests_mem);
	suite_add_tcase(s, tests_banned);

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
