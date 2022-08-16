/*
 * A library for secure removing files.
 *	-- public header file
 *
 * Copyright (C) 2007 Bogdan Drozdowski, bogdandr (at) op.pl
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

#ifndef _LIBSECRM_H
# define _LIBSECRM_H 1

# define _LARGEFILE64_SOURCE 1
/*# define _FILE_OFFSET_BITS 64*/

# include <sys/types.h>		/* mode_t, off_t, off64_t */
# include <stdio.h>		/* FILE */

#if (!defined __USE_FILE_OFFSET64) && (!defined __USE_LARGEFILE64)
typedef off_t off64_t;
#endif

/* PARAMS is a macro used to wrap function prototypes, so that
        compilers that don't understand ANSI C prototypes still work,
        and ANSI C compilers can issue warnings about type mismatches. */
# undef PARAMS
# if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
#  define PARAMS(protos) protos
# else
#  define PARAMS(protos) ()
# endif


# ifdef __cplusplus
extern "C" {
# endif

extern FILE* lsr_fopen64	PARAMS((const char * const name,
					const char * const mode));
extern FILE* lsr_fopen		PARAMS((const char * const name,
					const char * const mode));
extern FILE* lsr_freopen64	PARAMS((const char * const path,
					const char * const mode,
					FILE* stream));
extern FILE* lsr_freopen	PARAMS((const char * const name,
					const char * const mode,
					FILE* stream));
extern int lsr_open64		PARAMS((const char * const path,
					const int flags,
					...));
extern int lsr_open		PARAMS((const char * const name,
					const int flags,
					...));
extern int lsr_openat64		PARAMS((const int dirfd,
					const char * const pathname,
					const int flags,
					...));
extern int lsr_openat		PARAMS((const int dirfd,
					const char * const pathname,
					const int flags,
					...));
extern int lsr_truncate		PARAMS((const char * const path,
					const off_t length));
extern int lsr_truncate64	PARAMS((const char * const path,
					const off64_t length));
extern int lsr_ftruncate	PARAMS((int fd,
					const off_t length));
extern int lsr_ftruncate64	PARAMS((int fd,
					const off64_t length));
extern int lsr_unlink		PARAMS((const char * const name));
extern int lsr_unlinkat		PARAMS((const int dirfd,
					const char * const name,
					const int flags));
extern int lsr_remove		PARAMS((const char * const name));
extern int lsr_creat64		PARAMS((const char * const path,
					const mode_t mode));
extern int lsr_creat		PARAMS((const char * const path,
					const mode_t mode));

# ifdef __cplusplus
}
# endif

#endif	/* _LIBSECRM_H */

