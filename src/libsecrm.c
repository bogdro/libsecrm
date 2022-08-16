/*
 * A library for secure removing files.
 *
 * Copyright (C) 2007 Bogdan Drozdowski, bogdandr (at) op.pl
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

#if (defined HAVE_DLFCN_H) && (defined HAVE_DLSYM)
	/*&& (defined HAVE_LIBDL)*/
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

#ifdef HAVE_TIME_H
# include <time.h>	/* time() for randomization purposes */
#endif

#ifdef HAVE_STDLIB_H
# include <stdlib.h>	/* random(), srandom(), rand(), srand() */
#endif

 	/* need memset() */
#ifdef HAVE_STRING_H
# if (!STDC_HEADERS) && (defined HAVE_MEMORY_H)
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

int	is_initialized		= 0;

/* Pointers to original functions */
i_cp		__lsr_real_unlink	= NULL, __lsr_real_remove	= NULL;
i_i_cp_i	__lsr_real_unlinkat	= NULL;

i_cp_o64	__lsr_real_truncate64	= NULL;
i_i_o64		__lsr_real_ftruncate64	= NULL;
fp_cp_cp	__lsr_real_fopen64	= NULL;
fp_cp_cp_fp	__lsr_real_freopen64	= NULL;
i_cp_i_		__lsr_real_open64	= NULL;
i_i_cp_i_	__lsr_real_openat64	= NULL;
i_cp_mt		__lsr_real_creat64	= NULL;

i_cp_o		__lsr_real_truncate	= NULL;
i_i_o		__lsr_real_ftruncate	= NULL;
fp_cp_cp	__lsr_real_fopen	= NULL;
fp_cp_cp_fp	__lsr_real_freopen	= NULL;
i_cp_i_		__lsr_real_open		= NULL;
i_i_cp_i_	__lsr_real_openat	= NULL;
i_cp_mt		__lsr_real_creat	= NULL;

/* =============================================================== */

#if (defined __STRICT_ANSI__) || (!defined HAVE_SRANDOM) || (!defined HAVE_RANDOM)

static unsigned long next = 0xdeafface;

/* 'man rand': */
int __lsr_rand (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	void
#endif
)
{
	next = next * 1103515245 + 12345;
	return ((unsigned)(next/65536) % 32768);
}

static void __lsr_srand (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	unsigned int seed)
#else
	seed)
	unsigned int seed;
#endif
{
	next = seed;
}
#endif

/* =========== Setting signal handler and file lock ============== */

int __lsr_set_signal_lock (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	int * const fcntl_signal, const int fd,
	int * const fcntl_sig_old
# if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
	, struct sigaction * const sa,
	struct sigaction * const old_sa,
	int * const res_sig
# else
	, sighandler_t * const sig_hndlr
# endif
	)
#else
	fcntl_signal, fd, fcntl_sig_old
# if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
	, sa, old_sa, res_sig
# else
	, sig_hndlr
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
	*sig_hndlr = signal ( *fcntl_signal, &fcntl_signal_received );
	if ( (*sig_hndlr == SIG_ERR)
#   ifdef HAVE_ERRNO_H
		|| (errno != 0)
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
	(*sa).sa_handler = &fcntl_signal_received;
#   ifdef HAVE_ERRNO_H
	errno = 0;
#   endif
	*res_sig = sigaction ( *fcntl_signal, sa, old_sa );
	if ( (*res_sig != 0)
#   ifdef HAVE_ERRNO_H
		|| (errno != 0)
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
		|| (errno != 0)
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
	const int fcntl_signal, const int fd,
	const int fcntl_sig_old
# if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
	, const struct sigaction * const old_sa,
	const int res_sig
# else
	, const sighandler_t * const sig_hndlr
# endif
	)
#else
	fcntl_signal, fd, fcntl_sig_old
# if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
	, old_sa, res_sig
# else
	, sig_hndlr
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

	if ( is_initialized == 0 )
	{
#ifdef HAVE_ERRNO_H
		err = 0;
#endif
		/* Get pointers to the original functions: */

		*(void **) (&__lsr_real_unlink)      = dlsym  (RTLD_NEXT, "unlink");
		*(void **) (&__lsr_real_remove)      = dlsym  (RTLD_NEXT, "remove");
		*(void **) (&__lsr_real_unlinkat)    = dlsym  (RTLD_NEXT, "unlinkat");
		/* Libtrash: funny interaction fixed! when dlsym() was used instead of dlvsym(),
		   GNU libc would give us a pointer to an older version of fopen() and
		   subsequently crash if the calling code tried to use, e.g., getwc().
		   YES, THIS MUST BE 2.1 !
		   */
#if (defined HAVE_DLSYM) && (!defined HAVE_DLVSYM)	\
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
#if (defined HAVE_DLSYM) && (!defined HAVE_DLVSYM)	\
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

#if (!defined __STRICT_ANSI__) && (defined HAVE_SRANDOM) && (defined HAVE_RANDOM)
# ifdef HAVE_TIME_H
		srandom (0xdeafface*(unsigned long) time (NULL));
# else
		srandom (0xdeafface);
# endif

#else

# ifdef HAVE_TIME_H
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
		is_initialized = 1;
	}

	return 0;
}

#ifdef HAVE_SIGNAL_H
# ifndef RETSIGTYPE
#  define RETSIGTYPE void
#  undef RETSIG_ISINT
# endif
/* Signal-related stuff */
/* sig_atomic_t defined either in signal.h or libsecrm-priv.h */
volatile sig_atomic_t sig_recvd = 0;		/* non-zero after signal received */

/**
 * Signal handler - Sets a flag which will stop further program operations, when a
 * signal which would normally terminate the program is received.
 * \param signum Signal number.
 */
RETSIGTYPE
fcntl_signal_received (
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	const int signum )
#else
	signum )
	const int signum;
#endif
{
	sig_recvd = signum;
#ifdef RETSIG_ISINT
	return 0;
#endif
}
#endif

