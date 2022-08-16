/*
 * A library for secure removing files.
 *	-- private header file
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

# undef		NPAT
enum patterns	/* enum is just for GDB */
{
	NPAT = 22
};

# ifndef  PASSES
#  define PASSES (NPAT+3)
# else
#  if    PASSES < 1
#   undef  PASSES
#   define PASSES (NPAT+3)
#  endif
# endif

# ifndef  BUF_SIZE
#  define BUF_SIZE (1024*1024)
# else
#  if    (BUF_SIZE < 1) || (BUF_SIZE > 2147483647)
#   undef  BUF_SIZE
#   define BUF_SIZE (1024*1024)
#  endif
# endif

# define _LARGEFILE64_SOURCE 1
/*# define _FILE_OFFSET_BITS 64*/

# ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>	/* size_t, off_t (otherwise #define'd by 'configure'), off64_t */
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

# ifndef HAVE_MODE_T
typedef unsigned short mode_t;
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
#  ifndef creat64
#   define creat64	creat
#  endif
# endif

# ifdef HAVE_UNISTD_H
#  include <unistd.h>
# else
/* Only these need to be defined, because only these get called explicitly. */
extern int truncate PARAMS((const char *path, off_t length));
#  if (!defined truncate64)
extern int truncate64 PARAMS((const char *path, off64_t length));
#  endif
extern int ftruncate PARAMS((int fd, off_t length));
#  if (!defined ftruncate64)
extern int ftruncate64 PARAMS((int fd, off64_t length));
#  endif
# endif

# ifdef __GNUC__
#  ifndef strcat
#  pragma GCC poison strcat
#  endif
#  ifndef strcpy
#  pragma GCC poison strcpy
#  endif
#  pragma GCC poison gets fdopen __lsr_real_fdopen
# endif

typedef int	(*i_cp)		PARAMS((const char * const name));
typedef int	(*i_i_cp_i)	PARAMS((const int dir_fd, const char * const pathname, const int flags));
typedef int	(*i_cp_o)	PARAMS((const char * const path, const off_t length));
typedef int	(*i_i_o)	PARAMS((const int fd, const off_t length));
typedef FILE*	(*fp_cp_cp)	PARAMS((const char * const name, const char * const mode));
typedef FILE*	(*fp_cp_cp_fp)	PARAMS((const char * const name, const char * const mode, FILE* stream));
typedef int	(*i_cp_i_)	PARAMS((const char * const name, const int flags, ...));
typedef int	(*i_i_cp_i_)	PARAMS((const int dir_fd, const char * const pathname, const int flags, ...));
typedef int	(*i_cp_o64)	PARAMS((const char * const path, const off64_t length));
typedef int	(*i_i_o64)	PARAMS((const int fd, const off64_t length));
typedef int	(*i_cp_mt)	PARAMS((const char * const name, const mode_t mode));

extern GCC_WARN_UNUSED_RESULT LSR_ATTR ((nonnull)) i_cp
	__lsr_real_unlink, __lsr_real_remove;
extern GCC_WARN_UNUSED_RESULT LSR_ATTR ((nonnull)) i_i_cp_i	__lsr_real_unlinkat;

extern GCC_WARN_UNUSED_RESULT LSR_ATTR ((nonnull)) fp_cp_cp	__lsr_real_fopen64;
extern GCC_WARN_UNUSED_RESULT LSR_ATTR ((nonnull)) fp_cp_cp_fp	__lsr_real_freopen64;
extern GCC_WARN_UNUSED_RESULT LSR_ATTR ((nonnull)) i_cp_i_	__lsr_real_open64;
extern GCC_WARN_UNUSED_RESULT LSR_ATTR ((nonnull)) i_i_cp_i_	__lsr_real_openat64;
extern GCC_WARN_UNUSED_RESULT LSR_ATTR ((nonnull)) i_cp_o64	__lsr_real_truncate64;
extern GCC_WARN_UNUSED_RESULT			   i_i_o64	__lsr_real_ftruncate64;
extern GCC_WARN_UNUSED_RESULT LSR_ATTR ((nonnull)) i_cp_mt	__lsr_real_creat64;

extern GCC_WARN_UNUSED_RESULT LSR_ATTR ((nonnull)) fp_cp_cp	__lsr_real_fopen;
extern GCC_WARN_UNUSED_RESULT LSR_ATTR ((nonnull)) fp_cp_cp_fp	__lsr_real_freopen;
extern GCC_WARN_UNUSED_RESULT LSR_ATTR ((nonnull)) i_cp_i_	__lsr_real_open;
extern GCC_WARN_UNUSED_RESULT LSR_ATTR ((nonnull)) i_i_cp_i_	__lsr_real_openat;
extern GCC_WARN_UNUSED_RESULT LSR_ATTR ((nonnull)) i_cp_o	__lsr_real_truncate;
extern GCC_WARN_UNUSED_RESULT			   i_i_o	__lsr_real_ftruncate;
extern GCC_WARN_UNUSED_RESULT LSR_ATTR ((nonnull)) i_cp_mt	__lsr_real_creat;

/*# ifndef _ATFILE_SOURCE*/
# if (defined HAVE_RENAMEAT) && (!defined _ATFILE_SOURCE)
extern int LSR_ATTR ((nonnull)) renameat PARAMS((int old_dir_fd, const char *oldpath,
					  int new_dir_fd, const char *newpath));
# endif
# if (!defined HAVE_OPENAT)
	/*&& (!defined _ATFILE_SOURCE)*/
extern int openat   PARAMS((int dir_fd, const char * pathname, int flags, ...));
#  if (!defined openat64)
extern int openat64 PARAMS((int dir_fd, const char * pathname, int flags, ...));
#  endif
# endif
# if (!defined HAVE_UNLINKAT)
	/*&& (!defined _ATFILE_SOURCE)*/
extern int unlinkat PARAMS((int dir_fd, const char * pathname, int flags));
# endif

extern int __lsr_main (void);
extern int GCC_WARN_UNUSED_RESULT __lsr_rand PARAMS((void));
extern int GCC_WARN_UNUSED_RESULT __lsr_check_prog_ban PARAMS((void));
extern int GCC_WARN_UNUSED_RESULT __lsr_check_file_ban PARAMS((const char * const name));
extern int GCC_WARN_UNUSED_RESULT __lsr_check_file_ban_proc PARAMS((const char * const name));


# ifdef HAVE_SIGNAL_H
#  include <signal.h>
#  ifndef RETSIGTYPE
#   define RETSIGTYPE void
#  endif
#  ifndef HAVE_SIG_ATOMIC_T
typedef int sig_atomic_t;
#  endif
extern RETSIGTYPE fcntl_signal_received PARAMS((const int signum));
extern volatile sig_atomic_t sig_recvd;
#  if (defined __STRICT_ANSI__)
typedef void (*sighandler_t) PARAMS((int));
#  endif
# else
typedef void (*sighandler_t) PARAMS((int));
struct sigaction
{
	void     (*sa_handler)(int);
}
# endif		/* HAVE_SIGNAL_H */

extern int __lsr_set_signal_lock
#if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
	PARAMS(( int * const fcntl_signal, const int fd,
		int * const fcntl_signal_old,
		struct sigaction * const sa,
		struct sigaction * const old_sa,
		int * const res_sig
	));
#else
	PARAMS(( int * const fcntl_signal, const int fd,
		int * const fcntl_signal_old, sighandler_t * const sig_hndlr
	));
#endif

extern void __lsr_unset_signal_unlock
#if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
	PARAMS(( const int fcntl_signal, const int fd,
		const int fcntl_sig_old,
		const struct sigaction * const old_sa,
		const int res_sig
	));
#else
	PARAMS(( const int fcntl_signal, const int fd,
		const int fcntl_sig_old, const sighandler_t * const sig_hndlr
	));
#endif

extern int __lsr_fd_truncate (const int fd, const off64_t length);


extern const unsigned long int npasses;		/* lsr_truncate.c */

# if (PATH_STYLE==32) || (PATH_SEP==128)	/* unix or mac */
#  define PATH_SEP "/"
# else
#  define PATH_SEP "\\"
# endif

#endif /* LSR_HEADER */
