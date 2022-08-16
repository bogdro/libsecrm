/*
 * A library for secure removing files.
 *	-- header file
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

#ifndef LSR_HEADER
# define LSR_HEADER 1

# undef LSR_ATTR
# ifdef __GNUC__
#  define LSR_ATTR(x)	__attribute__(x)
# else
#  define LSR_ATTR(x)
# endif

# undef		NPAT
enum patterns {
	NPAT = 22
};

# ifndef  PASSES
#  define PASSES (NPAT+3)
# elif    PASSES < 1
#  undef  PASSES
#  define PASSES (NPAT+3)
# endif

# ifndef  BUF_SIZE
#  define BUF_SIZE (1024*1024)
# elif    (BUF_SIZE < 1) || (BUF_SIZE > 2147483647)
#  undef  BUF_SIZE
#  define BUF_SIZE (1024*1024)
# endif

# define _FILE_OFFSET_BITS 64

# ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>	/* size_t, off_t (otherwise #define'd by 'configure') */
# endif
# ifndef HAVE_SSIZE_T
typedef int ssize_t;
# endif
# ifndef HAVE_OFF64_T
#  ifdef HAVE_LONG_LONG
typedef long long off64_t;
#  else
typedef long off64_t;
#  endif
# endif

# include <stdio.h>		/* renameat() and FILE structure definition */

# if (defined __USE_FILE_OFFSET64) || (defined __USE_LARGEFILE64)
#  define LSR_USE64 1
# else
#  undef LSR_USE64
#  ifndef lseek64
#   define lseek64	lseek
#  endif
#  ifndef stat64
#   define stat64	stat
#  endif
#  ifndef fstat64
#   define fstat64	fstat
#  endif
#  ifndef lstat64
#   define lstat64	lstat
#  endif
#  ifndef fopen64
#   define fopen64	fopen
#  endif
#  ifndef freopen64
#   define freopen64	freopen
#  endif
#  ifndef open64
#   define open64	open
#  endif
#  ifndef openat64
#   define openat64	openat
#  endif
#  ifndef truncate64
#   define truncate64	truncate
#  endif
#  ifndef ftruncate64
#   define ftruncate64	ftruncate
#  endif
# endif

# ifdef HAVE_UNISTD_H
#  include <unistd.h>
# else
extern int truncate (const char *path, off_t length);
extern int truncate64 (const char *path, off64_t length);
# endif

# ifdef __GNUC__
#  pragma GCC poison gets strcat strcpy fdopen __lsr_real_fdopen
# endif

typedef int	(*i_cp)		(const char * const name);
typedef int	(*i_i_cp_i)	(const int dirfd, const char * const pathname, const int flags);
typedef int	(*i_cp_o)	(const char * const path, const off_t length);
typedef int	(*i_i_o)	(const int fd, const off_t length);
typedef FILE*	(*fp_cp_cp)	(const char * const name, const char * const mode);
typedef FILE*	(*fp_cp_cp_fp)	(const char * const name, const char * const mode, FILE* stream);
typedef int	(*i_cp_i_)	(const char * const name, const int flags, ...);
typedef int	(*i_i_cp_i_)	(const int dirfd, const char * const pathname, const int flags, ...);
typedef int	(*i_cp_o64)	(const char * const path, const off64_t length);
typedef int	(*i_i_o64)	(const int fd, const off64_t length);

extern LSR_ATTR ((warn_unused_result)) LSR_ATTR ((nonnull)) i_cp
	__lsr_real_unlink, __lsr_real_remove;
extern LSR_ATTR ((warn_unused_result)) LSR_ATTR ((nonnull)) i_i_cp_i	__lsr_real_unlinkat;

extern LSR_ATTR ((warn_unused_result)) LSR_ATTR ((nonnull)) fp_cp_cp	__lsr_real_fopen64;
extern LSR_ATTR ((warn_unused_result)) LSR_ATTR ((nonnull)) fp_cp_cp_fp	__lsr_real_freopen64;
extern LSR_ATTR ((warn_unused_result)) LSR_ATTR ((nonnull)) i_cp_i_	__lsr_real_open64;
extern LSR_ATTR ((warn_unused_result)) LSR_ATTR ((nonnull)) i_i_cp_i_	__lsr_real_openat64;
extern LSR_ATTR ((warn_unused_result)) LSR_ATTR ((nonnull)) i_cp_o64	__lsr_real_truncate64;
extern LSR_ATTR ((warn_unused_result))			    i_i_o64	__lsr_real_ftruncate64;

extern LSR_ATTR ((warn_unused_result)) LSR_ATTR ((nonnull)) fp_cp_cp	__lsr_real_fopen;
extern LSR_ATTR ((warn_unused_result)) LSR_ATTR ((nonnull)) fp_cp_cp_fp	__lsr_real_freopen;
extern LSR_ATTR ((warn_unused_result)) LSR_ATTR ((nonnull)) i_cp_i_	__lsr_real_open;
extern LSR_ATTR ((warn_unused_result)) LSR_ATTR ((nonnull)) i_i_cp_i_	__lsr_real_openat;
extern LSR_ATTR ((warn_unused_result)) LSR_ATTR ((nonnull)) i_cp_o	__lsr_real_truncate;
extern LSR_ATTR ((warn_unused_result))			    i_i_o	__lsr_real_ftruncate;

# ifndef _ATFILE_SOURCE
extern int LSR_ATTR ((nonnull)) renameat (int olddirfd, const char *oldpath,
					  int newdirfd, const char *newpath);
# endif

extern int __lsr_main (void);
extern int __lsr_rand (void);
extern int LSR_ATTR ((warn_unused_result)) __lsr_check_prog_ban (void);
extern int LSR_ATTR ((warn_unused_result)) __lsr_check_file_ban (const char * const name);


# ifdef HAVE_SIGNAL_H
#  include <signal.h>
#  ifndef RETSIGTYPE
#   define RETSIGTYPE void
#  endif
#  ifndef HAVE_SIG_ATOMIC_T
typedef int sig_atomic_t;
#  endif
extern RETSIGTYPE fcntl_signal_received ( const int signum );
extern volatile sig_atomic_t sig_recvd;
#  if (defined __STRICT_ANSI__)
typedef void (*sighandler_t) (int);
#  endif

# endif		/* HAVE_SIGNAL_H */

extern const unsigned long int npasses;

#endif /* LSR_HEADER */
