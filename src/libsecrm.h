/*
 * A library for secure removing files.
 *	-- header file
 *
 * Copyright (C) 2007 Bogdan Drozdowski, bogdandr (at) op.pl
 * License: GNU General Public License, v2+
 *
 * Syntax example: export LD_PRELOAD=/usr/local/lib/libsecrm.so
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
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

#ifndef LSR_HEADER
# define LSR_HEADER 1

# undef LSR_ATTR
# ifdef __GNUC__
#  define LSR_ATTR(x)	__attribute__(x)
# else
#  define LSR_ATTR(x)
# endif

# define	NPAT	22

# ifndef PASSES
#  define PASSES (NPAT+3)
# endif

# include "lsr_cfg.h"

# include <stdio.h>

# ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>	/* size_t, off_t (otherwise #define'd by ./configure) */
# endif

# ifdef HAVE_UNISTD_H
#  include <unistd.h>
# endif

typedef int	(*i_cp)		(const char*name);
typedef int	(*i_i_cp_i)	(int dirfd, const char *pathname, int flags);
typedef int	(*i_cp_o)	(const char *path, off_t length);
typedef int	(*i_i_o)	(int fd, off_t length);
typedef FILE*	(*fp_cp_cp)	(const char* name, const char* mode);
typedef FILE*	(*fp_cp_cp_fp)	(const char* name, const char*mode, FILE*);
typedef int	(*i_cp_i_)	(const char*name, int flags, ...);
typedef FILE*	(*fp_i_cp)	(int fildes, const char *mode);
typedef int	(*i_i_cp_i_)	(int dirfd, const char * const pathname, int flags, ...);

#ifdef __USE_FILE_OFFSET64
typedef int	(*i_cp_o64)	(const char *path, __off64_t length);
typedef int	(*i_i_o64)	(int fd, __off64_t length);
#endif

#ifndef HAVE_UNISTD_H
extern int truncate (const char *path, off_t length);
extern int truncate64 (const char *path, off64_t length);
#endif

extern LSR_ATTR((warn_unused_result)) LSR_ATTR((nonnull)) i_cp		__lsr_real_unlink;
extern LSR_ATTR((warn_unused_result)) LSR_ATTR((nonnull)) i_i_cp_i	__lsr_real_unlinkat;

extern LSR_ATTR((warn_unused_result)) LSR_ATTR((nonnull)) i_cp_o	__lsr_real_truncate;
extern LSR_ATTR((warn_unused_result))			  i_i_o		__lsr_real_ftruncate;
#ifdef __USE_FILE_OFFSET64
extern LSR_ATTR((warn_unused_result)) LSR_ATTR((nonnull)) i_cp_o64	__lsr_real_truncate64;
extern LSR_ATTR((warn_unused_result))			  i_i_o64	__lsr_real_ftruncate64;
#endif

extern LSR_ATTR((warn_unused_result)) LSR_ATTR((nonnull)) fp_cp_cp
	__lsr_real_fopen, __lsr_real_fopen64;
extern LSR_ATTR((warn_unused_result)) LSR_ATTR((nonnull)) fp_cp_cp_fp
	__lsr_real_freopen, __lsr_real_freopen64;
extern LSR_ATTR((warn_unused_result)) LSR_ATTR((nonnull)) i_cp_i_
	__lsr_real_open, __lsr_real_open64;
extern LSR_ATTR((warn_unused_result)) LSR_ATTR((nonnull)) fp_i_cp
	__lsr_real_fdopen;
extern LSR_ATTR((warn_unused_result)) LSR_ATTR((nonnull)) i_i_cp_i_
	__lsr_real_openat, __lsr_real_openat64;

extern int LSR_ATTR((nonnull)) renameat(int olddirfd, const char *oldpath,
					int newdirfd, const char *newpath);

extern int __lsr_main(void);

extern const unsigned long int npasses;

#endif /* LSR_HEADER */
