/*
 * LibSecRm - A library for secure removing files.
 *	-- unit test common functions - header file.
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

#ifndef LSRTEST_COMMON_HEADER
# define LSRTEST_COMMON_HEADER 1

# include <check.h>

/* compatibility with older 'check' versions */
# ifndef ck_abort
#  define ck_abort() ck_abort_msg(NULL)
#  define ck_abort_msg fail
#  define ck_assert(C) ck_assert_msg(C, NULL)
#  define ck_assert_msg fail_unless
# endif

# ifndef _ck_assert_int
#  define _ck_assert_int(X, O, Y) ck_assert_msg((X) O (Y), "Assertion '"#X#O#Y"' failed: "#X"==%d, "#Y"==%d", X, Y)
#  define ck_assert_int_eq(X, Y) _ck_assert_int(X, ==, Y)
#  define ck_assert_int_ne(X, Y) _ck_assert_int(X, !=, Y)
# endif

# ifndef _ck_assert_str
#  define _ck_assert_str(C, X, O, Y) ck_assert_msg(C, "Assertion '"#X#O#Y"' failed: "#X"==\"%s\", "#Y"==\"%s\"", X, Y)
#  define ck_assert_str_eq(X, Y) _ck_assert_str(!strcmp(X, Y), X, ==, Y)
#  define ck_assert_str_ne(X, Y) _ck_assert_str(strcmp(X, Y), X, !=, Y)
# endif

# ifndef GCC_WARN_UNUSED_RESULT
/*
 if the compiler doesn't support this, define this to an empty string,
 so that everything compiles (just in case)
 */
#  define GCC_WARN_UNUSED_RESULT /*LSR_ATTR((warn_unused_result))*/
# endif

/* LSR_PARAMS is a macro used to wrap function prototypes, so that
        compilers that don't understand ANSI C prototypes still work,
        and ANSI C compilers can issue warnings about type mismatches. */
# undef LSR_PARAMS
# if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
#  define LSR_PARAMS(protos) protos
#  define LSR_ANSIC
# else
#  define LSR_PARAMS(protos) ()
#  undef LSR_ANSIC
# endif

# define LSR_TEST_FILENAME "zz1"
# define LSR_TEST_FILE_LENGTH 3
# define LSR_TEST_FILE_EXT_LENGTH 100

# define LSR_LINK_FILENAME "zzl"
# define LSR_PIPE_FILENAME "zzpipe"

# define LSR_TEST_BANNED_FILENAME "sh-thd-12345"

# define LSR_TEST_DIRNAME "zz1dir"

# if (defined LSR_ENABLE_USERBANS) && (defined HAVE_GETENV) \
	&& (defined HAVE_STDLIB_H) && (defined HAVE_MALLOC)
#  define LSR_CAN_USE_BANS 1
# else
#  undef LSR_CAN_USE_BANS
# endif

# if (defined LSR_ENABLE_ENV) && (defined HAVE_STDLIB_H) && (defined HAVE_GETENV)
#  define LSR_CAN_USE_ENV 1
# else
#  undef LSR_CAN_USE_ENV
# endif

/*
# if (defined HAVE_SYS_TYPES_H) && (defined HAVE_SYS_STAT_H) && (defined HAVE_MKFIFO)
#  define LSR_CAN_USE_PIPE 1
# else
Pipes are disabled, because both ends need to be opened, otherwise, opening blocks
either the fixture or the test, or both. */
#  undef LSR_CAN_USE_PIPE
/*
# endif
*/

# define LSR_PROLOG_FOR_TEST() \
	lsrtest_set_inside_write (1); \
	puts(__func__); \
	lsrtest_set_inside_write (0); \
	lsrtest_set_nwritten (0); \
	lsrtest_set_nwritten_total (0)

typedef ssize_t (*def_write)(int fd, const void *buf, size_t count);
typedef int (*def_rename)(const char *oldpath, const char *newpath);

# ifdef __cplusplus
extern "C" {
# endif

extern GCC_WARN_UNUSED_RESULT size_t lsrtest_get_nwritten LSR_PARAMS((void));
extern void lsrtest_set_nwritten LSR_PARAMS((size_t s));

extern GCC_WARN_UNUSED_RESULT size_t lsrtest_get_nwritten_total LSR_PARAMS((void));
extern void lsrtest_set_nwritten_total LSR_PARAMS((size_t s));

extern GCC_WARN_UNUSED_RESULT long int lsrtest_was_in_write LSR_PARAMS((void));

extern GCC_WARN_UNUSED_RESULT int lsrtest_is_inside_write LSR_PARAMS((void));
extern void lsrtest_set_inside_write LSR_PARAMS((int v));

extern GCC_WARN_UNUSED_RESULT const char * lsrtest_get_last_name LSR_PARAMS((void));
extern void lsrtest_set_last_name LSR_PARAMS((const char newpath[]));

extern void lsrtest_prepare_banned_file LSR_PARAMS((void));
# ifdef LSR_CAN_USE_PIPE
extern void lsrtest_prepare_pipe LSR_PARAMS((void));
# endif

extern TCase * lsrtest_add_fixtures LSR_PARAMS((TCase * tests));

# ifdef __cplusplus
}
# endif

#endif /* LSRTEST_COMMON_HEADER */
