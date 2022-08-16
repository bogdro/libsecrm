/*
 * A library for secure removing data.
 *
 * Copyright (C) 2007-2009 Bogdan Drozdowski, bogdandr (at) op.pl
 * License: GNU General Public License, v3+
 *
 * Syntax example: export LD_PRELOAD=/usr/local/lib/libsecrm.so
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
 *
 * Thanks to:
 * - Manuel Arriaga for libtrash, parts of which are used here
 * - Colin Plumb, for the great 'shred' program, parts of which are used here.
 *   The 'shred' utility is:
 *	Copyright (C) 1999-2006 Free Software Foundation, Inc.
 *	Copyright (C) 1997, 1998, 1999 Colin Plumb.
 * - The authors of Libsafe for the great piece of software, parts of which
 *   are used here. Libsafe is:
 *	Copyright (C) 2002 Avaya Labs, Avaya Inc.
 *	Copyright (C) 1999 Bell Labs, Lucent Technologies.
 *	Copyright (C) Arash Baratloo, Timothy Tsai, and Navjot Singh.
 * - The authors of the "fuser" utility, parts of which are used here. Fuser is:
 *	Based on fuser.c Copyright (C) 1993-2005 Werner Almesberger and Craig Small
 *	Completely re-written
 *	Copyright (C) 2005 Craig Small
 *
 */

#include "lsr_cfg.h"

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
# if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
#  error Dynamic loading functions missing.
# endif
#endif

#include <stdio.h>

	/* time() for randomization purposes */
#ifdef TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  ifdef HAVE_TIME_H
#   include <time.h>
#  endif
# endif
#endif

#ifdef HAVE_STDLIB_H
# include <stdlib.h>	/* random(), srandom(), rand(), srand() */
#endif

 	/* need memset() */
#ifdef HAVE_STRING_H
# if (!defined STDC_HEADERS) && (defined HAVE_MEMORY_H)
#  include <memory.h>
# endif
# include <string.h>
#endif

#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif

#include "libsecrm-priv.h"

static int	__lsr_is_initialized	= 0;

/* Pointers to original functions */
static i_cp		__lsr_real_unlink	= NULL;
static i_cp		__lsr_real_remove	= NULL;
static i_i_cp_i		__lsr_real_unlinkat	= NULL;
static i_cp		__lsr_real_rmdir	= NULL;

static i_cp_o64		__lsr_real_truncate64	= NULL;
static i_i_o64		__lsr_real_ftruncate64	= NULL;
static fp_cp_cp		__lsr_real_fopen64	= NULL;
static fp_cp_cp_fp	__lsr_real_freopen64	= NULL;
static i_cp_i_		__lsr_real_open64	= NULL;
static i_i_cp_i_	__lsr_real_openat64	= NULL;
static i_cp_mt		__lsr_real_creat64	= NULL;

static i_cp_o		__lsr_real_truncate	= NULL;
static i_i_o		__lsr_real_ftruncate	= NULL;
static fp_cp_cp		__lsr_real_fopen	= NULL;
static fp_cp_cp_fp	__lsr_real_freopen	= NULL;
static i_cp_i_		__lsr_real_open		= NULL;
static i_i_cp_i_	__lsr_real_openat	= NULL;
static i_cp_mt		__lsr_real_creat	= NULL;

/* memory-related functions: */
static f_s		__lsr_real_malloc	= NULL;
static vpp_s_s		__lsr_real_psx_memalign	= NULL;
static f_s		__lsr_real_valloc	= NULL;
static f_s_s		__lsr_real_memalign	= NULL;
static f_vp		__lsr_real_brk		= NULL;
static f_ip		__lsr_real_sbrk		= NULL;

/* =============================================================== */

#if (defined __STRICT_ANSI__) || (!defined HAVE_SRANDOM) || (!defined HAVE_RANDOM)

static unsigned long __lsr_next = 0xdeafface;

/* 'man rand': */
int __lsr_rand (
# if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	void
# endif
)
{
	__lsr_next = __lsr_next * 1103515245 + 12345;
	return ((unsigned)(__lsr_next/65536) % 32768);
}

static void __lsr_srand (
# if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	unsigned int seed)
# else
	seed)
	unsigned int seed;
# endif
{
	__lsr_next = seed;
}
#endif

/* sig_atomic_t defined either in signal.h or libsecrm-priv.h. Has to be defined unconditionally. */
static volatile sig_atomic_t sig_recvd = 0;		/* non-zero after signal received */

#ifdef HAVE_SIGNAL_H
# ifndef RETSIGTYPE
#  define RETSIGTYPE void
# endif
/* Signal-related stuff */
RETSIGTYPE __lsr_fcntl_signal_received PARAMS((const int signum));
/**
 * Signal handler - Sets a flag which will stop further program operations, when a
 * signal which would normally terminate the program is received.
 * \param signum Signal number.
 */
RETSIGTYPE
__lsr_fcntl_signal_received (
# if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	const int signum )
# else
	signum )
	const int signum;
# endif
{
	sig_recvd = signum;
# define void 1
# define int 2
# if RETSIGTYPE != void
	return 0;
# endif
# undef int
# undef void
}
#endif /* HAVE_SIGNAL_H */

#if ! ((defined HAVE_FCNTL_H) && (defined F_SETLEASE)		&& \
	(defined HAVE_SIGNAL_H) && (defined HAVE_DECL_F_GETSIG) && \
	(defined HAVE_DECL_F_SETSIG) && HAVE_DECL_F_GETSIG && HAVE_DECL_F_SETSIG)
# define UNUSED	LSR_ATTR((unused))
#else
# define UNUSED
#endif

/* =========== Setting signal handler and file lock ============== */

int __lsr_set_signal_lock (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	int * const fcntl_signal UNUSED, const int fd UNUSED,
	int * const fcntl_sig_old UNUSED
# if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
	, struct sigaction * const sa UNUSED,
	struct sigaction * const old_sa UNUSED,
	int * const res_sig UNUSED
# else
	, sighandler_t * const sig_hndlr UNUSED
# endif
	)
#else
	fcntl_signal UNUSED, fd UNUSED, fcntl_sig_old UNUSED
# if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
	, sa UNUSED, old_sa UNUSED, res_sig UNUSED
# else
	, sig_hndlr UNUSED
# endif
	)
	int * const fcntl_signal;
	const int fd;
	int * const fcntl_sig_old;
# if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
	struct sigaction * const sa;
	struct sigaction * const old_sa;
	int * const res_sig;
# else
	sighandler_t * const sig_hndlr;
# endif
#endif
{
	int res = -1;

#if (defined HAVE_FCNTL_H) && (defined F_SETLEASE)
	int res_fcntl = 0;
# if (defined HAVE_SIGNAL_H) && (defined HAVE_DECL_F_GETSIG) && \
	(defined HAVE_DECL_F_SETSIG) && HAVE_DECL_F_GETSIG && HAVE_DECL_F_SETSIG

	res = 0;
	*fcntl_signal = fcntl (fd, F_GETSIG);

	if ( *fcntl_signal == 0 )
	{
#  ifdef SIGIO
		*fcntl_signal = SIGIO;
#  else
		*fcntl_signal = SIGPOLL; /* POSIX, so available */
#  endif
	}
	/* replace the uncatchables */
	if ( (*fcntl_signal == SIGSTOP) || (*fcntl_signal == SIGKILL) )
	{
		*fcntl_sig_old = *fcntl_signal;
#  ifdef SIGIO
		*fcntl_signal = SIGIO;
#  else
		*fcntl_signal = SIGTERM; /* POSIX, so available */
#  endif
		if ( fcntl (fd, F_SETSIG, *fcntl_signal) != 0 )
		{
			*fcntl_signal = 0;
		}
	}
	else
	{
		*fcntl_sig_old = 0;
	}
#  if (!defined HAVE_SIGACTION) || (defined __STRICT_ANSI__)
#   ifdef HAVE_ERRNO_H
	errno = 0;
#   endif
	*sig_hndlr = signal ( *fcntl_signal, &__lsr_fcntl_signal_received );
	if ( (*sig_hndlr == SIG_ERR)
#   ifdef HAVE_ERRNO_H
/*		|| (errno != 0)*/
#   endif
	)
	{
		if ( *fcntl_sig_old != 0 )
		{
			fcntl (fd, F_SETSIG, *fcntl_sig_old);
		}
		res = -1;
	}
#  else
#   ifdef HAVE_MEMSET
	memset (sa, 0, sizeof (struct sigaction));
#   else
	for ( i=0; i < sizeof (struct sigaction); i++ )
	{
		((char *)sa)[i] = '\0';
	}
#   endif
	(*sa).sa_handler = &__lsr_fcntl_signal_received;
#   ifdef HAVE_ERRNO_H
	errno = 0;
#   endif
	*res_sig = sigaction ( *fcntl_signal, sa, old_sa );
	if ( (*res_sig != 0)
#   ifdef HAVE_ERRNO_H
/*		|| (errno != 0)*/
#   endif
	)
	{
		if ( *fcntl_sig_old != 0 )
		{
			fcntl (fd, F_SETSIG, *fcntl_sig_old);
		}
		res = -1;
	}

#  endif
# endif	/* HAVE_SIGNAL_H */
# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	res_fcntl = fcntl (fd, F_SETLEASE, F_WRLCK);
	if ( (res_fcntl != 0)
# ifdef HAVE_ERRNO_H
/*		|| (errno != 0)*/
# endif
	)
	{
		if ( *fcntl_sig_old != 0 )
		{
			fcntl (fd, F_SETSIG, *fcntl_sig_old);
		}
		res = -2;
	}
#endif	/* (defined HAVE_FCNTL_H) && (defined F_SETLEASE) */

	return res;
}


/* =========== Resetting signal handler and releasing file lock ============== */

void __lsr_unset_signal_unlock (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	const int fcntl_signal UNUSED, const int fd UNUSED,
	const int fcntl_sig_old UNUSED
# if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
	, const struct sigaction * const old_sa UNUSED,
	const int res_sig UNUSED
# else
	, const sighandler_t * const sig_hndlr UNUSED
# endif
	)
#else
	fcntl_signal UNUSED, fd UNUSED, fcntl_sig_old UNUSED
# if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
	, old_sa UNUSED, res_sig UNUSED
# else
	, sig_hndlr UNUSED
# endif
	)
	const int fcntl_signal;
	const int fd;
	const int fcntl_sig_old;
# if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
	const struct sigaction * const old_sa;
	const int res_sig;
# else
	const sighandler_t * const sig_hndlr;
# endif
#endif
{

#if (defined HAVE_FCNTL_H) && (defined F_SETLEASE)
# if (defined HAVE_SIGNAL_H) && (defined HAVE_DECL_F_SETSIG) && (HAVE_DECL_F_SETSIG)
	fcntl (fd, F_SETLEASE, F_UNLCK);

#  if (!defined HAVE_SIGACTION) || (defined __STRICT_ANSI__)
	if ( sig_hndlr != SIG_ERR )
	{
		if ( (fcntl_sig_old == 0) || (fcntl_signal != 0) )
		{
			signal ( fcntl_signal, sig_hndlr );
		}
		else
		{
			signal ( fcntl_sig_old, sig_hndlr );
		}
	}
#  else
	if ( res_sig == 0 )
	{
		if ( (fcntl_sig_old == 0) || (fcntl_signal != 0) )
		{
			sigaction ( fcntl_signal, old_sa, NULL );
		}
		else
		{
			sigaction ( fcntl_sig_old, old_sa, NULL );
		}
	}
#  endif
	if ( fcntl_sig_old != 0 )
	{
		fcntl (fd, F_SETSIG, fcntl_sig_old);
	}
# endif		/* HAVE_SIGNAL_H */
#endif

}

/* =============================================================== */

int LSR_ATTR ((constructor))
__lsr_main (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	void
#endif
)
{
#ifdef HAVE_ERRNO_H
	int err;
#endif

	if ( __lsr_is_initialized == 0 )
	{
#ifdef HAVE_ERRNO_H
		err = 0;
#endif
		/* Get pointers to the original functions: */

		*(void **) (&__lsr_real_unlink)      = dlsym  (RTLD_NEXT, "unlink");
		*(void **) (&__lsr_real_remove)      = dlsym  (RTLD_NEXT, "remove");
		*(void **) (&__lsr_real_unlinkat)    = dlsym  (RTLD_NEXT, "unlinkat");
		*(void **) (&__lsr_real_rmdir)       = dlsym  (RTLD_NEXT, "rmdir");
		/* Libtrash: funny interaction fixed! when dlsym() was used instead of dlvsym(),
		   GNU libc would give us a pointer to an older version of fopen() and
		   subsequently crash if the calling code tried to use, e.g., getwc().
		   YES, THIS MUST BE 2.1 !
		   */
#if (defined HAVE_DLSYM || defined HAVE_LIBDL_DLSYM)			\
	&& (!defined HAVE_DLVSYM) && (!defined HAVE_LIBDL_DLVSYM)	\
	|| ( defined __GLIBC__ && (__GLIBC__ < 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ < 1) ) )
		*(void **) (&__lsr_real_fopen64)     = dlsym  (RTLD_NEXT, "fopen64");
#else
		*(void **) (&__lsr_real_fopen64)     = dlvsym (RTLD_NEXT, "fopen64", "GLIBC_2.1");
#endif
		*(void **) (&__lsr_real_freopen64)   = dlsym  (RTLD_NEXT, "freopen64");
		*(void **) (&__lsr_real_open64)      = dlsym  (RTLD_NEXT, "open64");
		*(void **) (&__lsr_real_openat64)    = dlsym  (RTLD_NEXT, "openat64");

		*(void **) (&__lsr_real_truncate64)  = dlsym  (RTLD_NEXT, "truncate64");
		*(void **) (&__lsr_real_ftruncate64) = dlsym  (RTLD_NEXT, "ftruncate64");
		*(void **) (&__lsr_real_creat64)     = dlsym  (RTLD_NEXT, "creat64");
#if (defined HAVE_DLSYM || defined HAVE_LIBDL_DLSYM)			\
	&& (!defined HAVE_DLVSYM) && (!defined HAVE_LIBDL_DLVSYM)	\
	|| ( defined __GLIBC__ && (__GLIBC__ < 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ < 1) ) )
		*(void **) (&__lsr_real_fopen)       = dlsym  (RTLD_NEXT, "fopen");
#else
		*(void **) (&__lsr_real_fopen)       = dlvsym (RTLD_NEXT, "fopen", "GLIBC_2.1");
#endif
		*(void **) (&__lsr_real_freopen)     = dlsym  (RTLD_NEXT, "freopen");
		*(void **) (&__lsr_real_open)        = dlsym  (RTLD_NEXT, "open");
		*(void **) (&__lsr_real_openat)      = dlsym  (RTLD_NEXT, "openat");

		*(void **) (&__lsr_real_truncate)    = dlsym  (RTLD_NEXT, "truncate");
		*(void **) (&__lsr_real_ftruncate)   = dlsym  (RTLD_NEXT, "ftruncate");
		*(void **) (&__lsr_real_creat)       = dlsym  (RTLD_NEXT, "creat");

		/* memory-related functions: */
		*(void **) (&__lsr_real_malloc)      = dlsym  (RTLD_NEXT, "malloc");
		*(void **) (&__lsr_real_psx_memalign)= dlsym  (RTLD_NEXT, "posix_memalign");
		*(void **) (&__lsr_real_valloc)      = dlsym  (RTLD_NEXT, "valloc");
		*(void **) (&__lsr_real_memalign)    = dlsym  (RTLD_NEXT, "memalign");
		*(void **) (&__lsr_real_brk)         = dlsym  (RTLD_NEXT, "brk");
		*(void **) (&__lsr_real_sbrk)        = dlsym  (RTLD_NEXT, "sbrk");


#if (!defined __STRICT_ANSI__) && (defined HAVE_SRANDOM) && (defined HAVE_RANDOM)
# if (defined HAVE_TIME_H) || (defined HAVE_SYS_TIME_H) || (defined TIME_WITH_SYS_TIME)
		srandom (0xdeafface*(unsigned long) time (NULL));
# else
		srandom (0xdeafface);
# endif

#else

# if (defined HAVE_TIME_H) || (defined HAVE_SYS_TIME_H) || (defined TIME_WITH_SYS_TIME)
		__lsr_srand(0xdeafface*(unsigned long) time (NULL));
		/*srand (0xdeafface*(unsigned long) time (NULL));*/
# else
		__lsr_srand(0xdeafface);
		/*srand (0xdeafface);*/
# endif
#endif
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
#ifdef HAVE_SIGNAL_H
		sig_recvd = 0;
#endif
		__lsr_is_initialized = 1;
	}

	return 0;
}

/**
 * Tells if a signal was received.
 * \return non-zero after a signal was received.
 */
sig_atomic_t
__lsr_sig_recvd (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	void
#endif
)
{
	return sig_recvd;
}
/* =============================================================== */
/* Functions returning pointers to real functions: */
/* =============================================================== */

i_cp		__lsr_real_unlink_location (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	void
#endif
)
{
	return __lsr_real_unlink;
}

i_cp		__lsr_real_remove_location (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	void
#endif
)
{
	return __lsr_real_remove;
}

i_i_cp_i		__lsr_real_unlinkat_location (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	void
#endif
)
{
	return __lsr_real_unlinkat;
}

i_cp		__lsr_real_rmdir_location (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	void
#endif
)
{
	return __lsr_real_rmdir;
}


fp_cp_cp		__lsr_real_fopen64_location (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	void
#endif
)
{
	return __lsr_real_fopen64;
}

fp_cp_cp_fp	__lsr_real_freopen64_location (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	void
#endif
)
{
	return __lsr_real_freopen64;
}

i_cp_i_		__lsr_real_open64_location (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	void
#endif
)
{
	return __lsr_real_open64;
}

i_i_cp_i_		__lsr_real_openat64_location (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	void
#endif
)
{
	return __lsr_real_openat64;
}

i_cp_o64		__lsr_real_truncate64_location (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	void
#endif
)
{
	return __lsr_real_truncate64;
}

i_i_o64		__lsr_real_ftruncate64_location (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	void
#endif
)
{
	return __lsr_real_ftruncate64;
}

i_cp_mt		__lsr_real_creat64_location (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	void
#endif
)
{
	return __lsr_real_creat64;
}


fp_cp_cp		__lsr_real_fopen_location (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	void
#endif
)
{
	return __lsr_real_fopen;
}

fp_cp_cp_fp	__lsr_real_freopen_location (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	void
#endif
)
{
	return __lsr_real_freopen;
}

i_cp_i_		__lsr_real_open_location (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	void
#endif
)
{
	return __lsr_real_open;
}

i_i_cp_i_		__lsr_real_openat_location (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	void
#endif
)
{
	return __lsr_real_openat;
}

i_cp_o		__lsr_real_truncate_location (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	void
#endif
)
{
	return __lsr_real_truncate;
}

i_i_o		__lsr_real_ftruncate_location (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	void
#endif
)
{
	return __lsr_real_ftruncate;
}

i_cp_mt		__lsr_real_creat_location (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	void
#endif
)
{
	return __lsr_real_creat;
}


/* memory-related functions: */
f_s		__lsr_real_malloc_location (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	void
#endif
)
{
	return __lsr_real_malloc;
}

vpp_s_s		__lsr_real_psx_memalign_location (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	void
#endif
)
{
	return __lsr_real_psx_memalign;
}

f_s		__lsr_real_valloc_location (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	void
#endif
)
{
	return __lsr_real_valloc;
}

f_s_s		__lsr_real_memalign_location (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	void
#endif
)
{
	return __lsr_real_memalign;
}

f_vp		__lsr_real_brk_location (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	void
#endif
)
{
	return __lsr_real_brk;
}

f_ip		__lsr_real_sbrk_location (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	void
#endif
)
{
	return __lsr_real_sbrk;
}

