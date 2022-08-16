/*
 * A library for secure removing files.
 *	-- wiping-related functions.
 *
 * Copyright (C) 2007-2019 Bogdan Drozdowski, bogdandr (at) op.pl
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

#include "lsr_cfg.h"

#ifndef _GNU_SOURCE
# define _GNU_SOURCE	1	/* need F_SETLEASE, fsync(), fallocate() */
#endif

#ifdef HAVE_STRING_H
# if (!defined STDC_HEADERS) && (defined HAVE_MEMORY_H)
#  include <memory.h>
# endif
# include <string.h>
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>	/* size_t, off_t (otherwise #define'd by ./configure) */
#endif

#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif

#ifdef HAVE_MALLOC_H
# include <malloc.h>
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#include <stdio.h>

#ifdef HAVE_STDLIB_H
# include <stdlib.h>	/* random(), rand() */
#endif

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif

#ifdef HAVE_SIGNAL_H
# include <signal.h>
# ifndef RETSIGTYPE
#  define RETSIGTYPE void
# endif
# ifndef HAVE_SIG_ATOMIC_T
typedef int sig_atomic_t;
# endif
#endif

#include "lsr_priv.h"

#ifdef __GNUC__
# ifndef fopen
#  pragma GCC poison fopen
# endif
# ifndef open
#  pragma GCC poison open
# endif
# ifndef freopen
#  pragma GCC poison freopen
# endif
# ifndef openat
#  pragma GCC poison openat
# endif
# ifndef open64
#  pragma GCC poison open64
# endif
# ifndef fopen64
#  pragma GCC poison fopen64
# endif
# ifndef freopen64
#  pragma GCC poison freopen64
# endif
# ifndef openat64
#  pragma GCC poison openat64
# endif
#endif

enum lsr_method
{
	LSR_METHOD_GUTMANN,
	LSR_METHOD_RANDOM,
	LSR_METHOD_SCHNEIER,
	LSR_METHOD_DOD
};

static enum lsr_method opt_method = LSR_METHOD_GUTMANN;

static const unsigned long int npasses = LSR_PASSES;	/* Number of passes (patterns used) */

/* Taken from `shred' source */
static const unsigned int patterns_random[] =
{
	0x000, 0xFFF,					/* 1-bit */
	0x555, 0xAAA,					/* 2-bit */
	0x249, 0x492, 0x6DB, 0x924, 0xB6D, 0xDB6,	/* 3-bit */
	0x111, 0x222, 0x333, 0x444, 0x666, 0x777,
	0x888, 0x999, 0xBBB, 0xCCC, 0xDDD, 0xEEE	/* 4-bit */
};

static const unsigned int patterns_gutmann[] =
{
	0x000, 0xFFF,					/* 1-bit */
	0x555, 0xAAA,					/* 2-bit */
	0x249, 0x492, 0x6DB, 0x924, 0xB6D, 0xDB6,	/* 3-bit */
	0x111, 0x222, 0x333, 0x444, 0x666, 0x777,
	0x888, 0x999, 0xBBB, 0xCCC, 0xDDD, 0xEEE,	/* 4-bit */
	/* Gutmann method says these are used twice. */
	0x555, 0xAAA, 0x249, 0x492, 0x924
};

static const unsigned int patterns_schneier[] =
{
	0xFFF, 0x000
};

static unsigned int patterns_dod[] =
{
	0xFFFFFFFF, 0x000	/* will be filled in later */
};

#undef	N_BYTES
#define N_BYTES	1024

#ifndef HAVE_MALLOC
static unsigned char __lsr_buffer[N_BYTES];
#endif

/* ======================================================= */

#ifndef LSR_ANSIC
static int lsr_is_pass_random LSR_PARAMS ((const unsigned long int pat_no,
	const enum lsr_method method));
#endif

/**
 * Tells if the given wiping pass for the given method should be using a random pattern.
 * \param pat_no Pass number.
 * \param method The wiping method.
 * \return 1 if the should be random, 0 otherwise.
 */
static int
lsr_is_pass_random (
#ifdef LSR_ANSIC
	const unsigned long int pat_no, const enum lsr_method method)
#else
	pat_no, method)
	const unsigned long int pat_no;
	const enum lsr_method method;
#endif
{
	if ( method == LSR_METHOD_GUTMANN )
	{
		/* Gutmann method: first 4, 1 middle and last 4 passes are random */
		if ( (pat_no == 0) || (pat_no == npasses-1) || (pat_no == npasses/2)
			|| (pat_no == 1) || (pat_no == 2) || (pat_no == 3)
			|| (pat_no == npasses-2) || (pat_no == npasses-3)
			|| (pat_no == npasses-4) )
		{
			return 1;
		}
	}
	else if ( method == LSR_METHOD_RANDOM )
	{
		/* The first, last and middle passess will be using a random pattern */
		if ( (pat_no == 0) || (pat_no == npasses-1) || (pat_no == npasses/2) )
		{
			return 1;
		}
	}
	else if ( method == LSR_METHOD_SCHNEIER )
	{
		/* the third (number 2 when indexed from 0) and later passes are random */
		if ( pat_no >= 2 )
		{
			return 1;
		}
	}
	else if ( method == LSR_METHOD_DOD )
	{
		/* the third (number 2 when indexed from 0) pass is random */
		if ( pat_no >= 2 )
		{
			return 1;
		}
	}
	return 0;
}

/* ======================================================= */

/**
 * Gets the number of passes.
 * \return the number of passes.
 */
unsigned long int
__lsr_get_npasses (LSR_VOID)
{
	return npasses;
}

/* ======================================================= */

#ifndef LSR_ANSIC
static sig_atomic_t __lsr_sig_recvd LSR_PARAMS ((void));
#endif

static volatile sig_atomic_t sig_recvd = 0;		/* non-zero after signal received */

/**
 * Tells if a signal was received.
 * \return non-zero after a signal was received.
 */
static sig_atomic_t
__lsr_sig_recvd (LSR_VOID)
{
	return sig_recvd;
}

/* ======================================================= */

/**
 * Fills the given buffer with one of predefined patterns.
 * \param pat_no Pass number.
 * \param buffer Buffer to be filled.
 * \param buflen Length of the buffer.
 * \param selected array with 0s or 1s telling which patterns are already selected
 */
void
#ifdef LSR_ANSIC
LSR_ATTR ((nonnull))
#endif
__lsr_fill_buffer (
#ifdef LSR_ANSIC
		unsigned long int 		pat_no,
		unsigned char * const 		buffer,
		const size_t 			buflen,
		int * const			selected )
#else
	pat_no, buffer, buflen, selected )
	unsigned long int 		pat_no;
	unsigned char * const 		buffer;
	const size_t 			buflen;
	int * const			selected;
#endif
		/*@requires notnull buffer @*/ /*@sets *buffer @*/
{
	size_t i;
	unsigned int bits;
	size_t npat;

	if ( (buffer == NULL) || (buflen == 0) || (selected == NULL) )
	{
		return;
	}

	if ( patterns_dod[0] == 0xFFFFFFFF )
	{
		/* Not initialized. Perform initialization. */
#ifdef LSR_WANT_RANDOM
		opt_method = LSR_METHOD_RANDOM;
#else
# ifdef LSR_WANT_SCHNEIER
		opt_method = LSR_METHOD_SCHNEIER;
# else
#  ifdef LSR_WANT_DOD
		opt_method = LSR_METHOD_DOD;
#  else
		opt_method = LSR_METHOD_GUTMANN;
#  endif
# endif
#endif

#if (!defined __STRICT_ANSI__) && (defined HAVE_RANDOM)
		patterns_dod[0] = (unsigned int)(random () & 0xFFF);
#else
		patterns_dod[0] = (unsigned int)(rand () & 0xFFF);
#endif
		patterns_dod[1] = (~patterns_dod[0]) & 0xFFF;
	}

	if ( opt_method == LSR_METHOD_GUTMANN )
	{
		npat = sizeof (patterns_gutmann)/sizeof (patterns_gutmann[0]);
	}
	else if ( opt_method == LSR_METHOD_RANDOM )
	{
		npat = sizeof (patterns_random)/sizeof (patterns_random[0]);
	}
	else if ( opt_method == LSR_METHOD_SCHNEIER )
	{
		npat = sizeof (patterns_schneier)/sizeof (patterns_schneier[0]);
	}
	else if ( opt_method == LSR_METHOD_DOD )
	{
		npat = sizeof (patterns_dod)/sizeof (patterns_dod[0]);
	}
	else
	{
		return;
	}

	for ( i = 0; i < npat; i++ )
	{
		if ( selected[i] == 0 )
		{
			break;
		}
	}
	if ( (i >= npat) && (lsr_is_pass_random (pat_no, opt_method) != 1) )
	{
		/* no patterns left and this is not a "random" pass - deselect all the patterns */
		for ( i = 0; (i < npat) && (__lsr_sig_recvd () == 0); i++ )
		{
			selected[i] = 0;
		}
	}
        pat_no %= npasses;

#ifdef ALL_PASSES_ZERO
	bits = 0;
#else
	if ( lsr_is_pass_random (pat_no, opt_method) == 1 )
	{
# if (!defined __STRICT_ANSI__) && (defined HAVE_RANDOM)
		bits = (unsigned int) ((size_t)random () & 0xFFF);
# else
		bits = (unsigned int) ((size_t)rand () & 0xFFF);
# endif
	}
	else
	{	/* For other passes, one of the fixed patterns is selected. */
		if ( (opt_method == LSR_METHOD_GUTMANN)
			|| (opt_method == LSR_METHOD_RANDOM) )
		{
			do
			{
# if (!defined __STRICT_ANSI__) && (defined HAVE_RANDOM)
				i = (size_t) ((size_t)random () % npat);
# else
				i = (size_t) ((size_t)rand () % npat);
# endif
			}
			while ( (selected[i] == 1) && (__lsr_sig_recvd () == 0) );
			if ( __lsr_sig_recvd () != 0 )
			{
				return;
			}
		}
		else
		{
			/* other methods use their patterns in sequence */
			i = pat_no;
		}
		if ( opt_method == LSR_METHOD_GUTMANN )
		{
			bits = patterns_gutmann[i];
		}
		else if ( opt_method == LSR_METHOD_RANDOM )
		{
			bits = patterns_random[i];
		}
		else if ( opt_method == LSR_METHOD_SCHNEIER )
		{
			bits = patterns_schneier[i];
		}
		else /*if ( opt_method == LSR_METHOD_DOD )*/
		{
			bits = patterns_dod[i] & 0xFFF;
		}
		selected[i] = 1;
	}

#endif /* ALL_PASSES_ZERO */
	/* Taken from `shred' source and modified */
	bits |= bits << 12;

#ifdef LSR_DEBUG
# ifndef ALL_PASSES_ZERO
	if ( lsr_is_pass_random (pat_no, opt_method) == 1 )
	{
		fprintf (stderr, "libsecrm: Using pattern (random)\n");
	}
	else
# endif /* ALL_PASSES_ZERO */
	{
		fprintf (stderr, "libsecrm: Using pattern %02x%02x%02x\n",
			(unsigned char) ((bits >> 4) & 0xFF),
			(unsigned char) ((bits >> 8) & 0xFF),
			(unsigned char) (bits & 0xFF) );
	}
#endif

	buffer[0] = (unsigned char) ((bits >> 4) & 0xFF);
	if ( buflen > 1 )
	{
		buffer[1] = (unsigned char) ((bits >> 8) & 0xFF);
	}
	if ( buflen > 2 )
	{
		buffer[2] = (unsigned char) (bits & 0xFF);
	}
	for (i = 3; (i << 1) < buflen; i <<= 1)
	{
		LSR_MEMCOPY (buffer + i, buffer, i);
	}
	if (i < buflen)
	{
		LSR_MEMCOPY (buffer + i, buffer, buflen - i);
	}
}

/* =============================================================== */

#ifndef LSR_ANSIC

# ifdef HAVE_SIGNAL_H
#  if (defined __STRICT_ANSI__)
typedef void (*sighandler_t) LSR_PARAMS ((int));
#  endif
# else		/* ! HAVE_SIGNAL_H */
/* dummy types: */
typedef void (*sighandler_t) LSR_PARAMS ((int));
struct sigaction
{
	void     (*sa_handler) LSR_PARAMS ((int));
}
# endif		/* HAVE_SIGNAL_H */

static int __lsr_set_signal_lock
# if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
	LSR_PARAMS (( int * const fcntl_signal, const int fd,
		int * const fcntl_signal_old,
		struct sigaction * const sa,
		struct sigaction * const old_sa,
		int * const res_sig
	));
# else
	LSR_PARAMS (( int * const fcntl_signal, const int fd,
		int * const fcntl_signal_old, sighandler_t * const sig_hndlr
	));
# endif

static void __lsr_unset_signal_unlock
# if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
	LSR_PARAMS (( const int fcntl_signal, const int fd,
		const int fcntl_sig_old,
		const struct sigaction * const old_sa,
		const int res_sig
	));
# else
	LSR_PARAMS (( const int fcntl_signal, const int fd,
		const int fcntl_sig_old, const sighandler_t * const sig_hndlr
	));
# endif

#endif

/* ======================================================= */

#ifdef HAVE_SIGNAL_H
# ifndef RETSIGTYPE
#  define RETSIGTYPE void
# endif
/* Signal-related stuff */
# ifndef LSR_ANSIC
static RETSIGTYPE __lsr_fcntl_signal_received LSR_PARAMS((const int signum));
# endif

/**
 * Signal handler - Sets a flag which will stop further program operations, when a
 * signal which would normally terminate the program is received.
 * \param signum Signal number.
 */
static RETSIGTYPE
__lsr_fcntl_signal_received (
# ifdef LSR_ANSIC
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
# define LSR_ONLY_WITH_FCNTL_SIGNALS	LSR_ATTR((unused))
#else
# define LSR_ONLY_WITH_FCNTL_SIGNALS
#endif

/* =========== Setting signal handler and file lock ============== */

static int __lsr_set_signal_lock (
#ifdef LSR_ANSIC
	int * const fcntl_signal LSR_ONLY_WITH_FCNTL_SIGNALS,
	const int fd LSR_ONLY_WITH_FCNTL_SIGNALS,
	int * const fcntl_sig_old LSR_ONLY_WITH_FCNTL_SIGNALS
# if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
	, struct sigaction * const sa LSR_ONLY_WITH_FCNTL_SIGNALS,
	struct sigaction * const old_sa LSR_ONLY_WITH_FCNTL_SIGNALS,
	int * const res_sig LSR_ONLY_WITH_FCNTL_SIGNALS
# else
	, sighandler_t * const sig_hndlr LSR_ONLY_WITH_FCNTL_SIGNALS
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
	int * const fcntl_signal LSR_ONLY_WITH_FCNTL_SIGNALS;
	const int fd LSR_ONLY_WITH_FCNTL_SIGNALS;
	int * const fcntl_sig_old LSR_ONLY_WITH_FCNTL_SIGNALS;
# if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
	struct sigaction * const sa LSR_ONLY_WITH_FCNTL_SIGNALS;
	struct sigaction * const old_sa LSR_ONLY_WITH_FCNTL_SIGNALS;
	int * const res_sig LSR_ONLY_WITH_FCNTL_SIGNALS;
# else
	sighandler_t * const sig_hndlr LSR_ONLY_WITH_FCNTL_SIGNALS;
# endif
#endif
{
	int res = -1;

#if (defined HAVE_FCNTL_H) && (defined F_SETLEASE)
	int res_fcntl = 0;
# if (defined HAVE_SIGNAL_H) && (defined HAVE_DECL_F_GETSIG) && \
	(defined HAVE_DECL_F_SETSIG) && HAVE_DECL_F_GETSIG && HAVE_DECL_F_SETSIG

	if ( (fcntl_signal == NULL) || (fcntl_sig_old == NULL) )
	{
		return res;
	}
#  if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
	if ( (sa == NULL) || (old_sa == NULL) || (res_sig == NULL) )
	{
		return res;
	}
#  else
	if ( sig_hndlr == NULL )
	{
		return res;
	}
#  endif
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
	*sig_hndlr = signal ( *fcntl_signal, &__lsr_fcntl_signal_received );
	if ( *sig_hndlr == SIG_ERR )
	{
		if ( *fcntl_sig_old != 0 )
		{
			fcntl (fd, F_SETSIG, *fcntl_sig_old);
		}
		res = -1;
	}
#  else
	LSR_MEMSET (sa, 0, sizeof (struct sigaction));
	(*sa).sa_handler = &__lsr_fcntl_signal_received;
	*res_sig = sigaction ( *fcntl_signal, sa, old_sa );
	if ( *res_sig != 0 )
	{
		if ( *fcntl_sig_old != 0 )
		{
			fcntl (fd, F_SETSIG, *fcntl_sig_old);
		}
		res = -1;
	}

#  endif
# endif	/* HAVE_SIGNAL_H */
	res_fcntl = fcntl (fd, F_SETLEASE, F_WRLCK);
	if ( res_fcntl != 0 )
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

static void __lsr_unset_signal_unlock (
#ifdef LSR_ANSIC
	const int fcntl_signal LSR_ONLY_WITH_FCNTL_SIGNALS,
	const int fd LSR_ONLY_WITH_FCNTL_SIGNALS,
	const int fcntl_sig_old LSR_ONLY_WITH_FCNTL_SIGNALS
# if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
	, const struct sigaction * const old_sa LSR_ONLY_WITH_FCNTL_SIGNALS,
	const int res_sig LSR_ONLY_WITH_FCNTL_SIGNALS
# else
	, const sighandler_t * const sig_hndlr LSR_ONLY_WITH_FCNTL_SIGNALS
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
	const int fcntl_signal LSR_ONLY_WITH_FCNTL_SIGNALS;
	const int fd LSR_ONLY_WITH_FCNTL_SIGNALS;
	const int fcntl_sig_old LSR_ONLY_WITH_FCNTL_SIGNALS;
# if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
	const struct sigaction * const old_sa LSR_ONLY_WITH_FCNTL_SIGNALS;
	const int res_sig LSR_ONLY_WITH_FCNTL_SIGNALS;
# else
	const sighandler_t * const sig_hndlr LSR_ONLY_WITH_FCNTL_SIGNALS;
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

/* ======================================================= */

#ifdef HAVE_UNISTD_H
int
__lsr_fd_truncate (
# ifdef LSR_ANSIC
	const int fd, const off64_t length)
# else
	fd, length)
	const int fd;
	const off64_t length;
# endif
{
	unsigned char /*@only@*/ *buf = NULL;		/* Buffer to be written to file blocks */
	int selected[LSR_NPAT] = {0};
# ifndef HAVE_LONG_LONG
	unsigned long int diff;
	unsigned int i;
	unsigned int nbuffers;
# else
	unsigned long long int diff;
	unsigned long long int i;
	unsigned long long int nbuffers;
# endif
	off64_t size;
	off64_t pos;
	size_t write_len;
	ssize_t write_res;
	unsigned int j;
	const size_t buffer_size = sizeof (unsigned char) * N_BYTES;
# ifdef HAVE_SYS_STAT_H
	struct stat s;
# endif
# ifdef HAVE_SIGNAL_H
	int res_sig;
	int fcntl_signal, fcntl_sig_old;
#  if (!defined HAVE_SIGACTION) || (defined __STRICT_ANSI__)
	sighandler_t sig_hndlr;
#  else
	struct sigaction sa, old_sa;
#  endif
# endif

	if ( fd < 0 )
	{
		return -1;
	}

	__lsr_main ();
# ifdef LSR_DEBUG
#  ifndef HAVE_LONG_LONG
	fprintf (stderr, "libsecrm: __lsr_fd_truncate(fd=%d, len=%ld)\n", fd, length);
#  else
	fprintf (stderr, "libsecrm: __lsr_fd_truncate(fd=%d, len=%lld)\n", fd, length);
#  endif
	fflush (stderr);
# endif

# if (defined HAVE_SYS_STAT_H) && (defined HAVE_FSTAT)
	if ( fstat (fd, &s) == 0 )
	{
		/* don't operate on non-regular files */
		if ( !S_ISREG (s.st_mode) )
		{
			return -1;
		}
	}
	else
	{
		return -1;
	}
# else /* !((defined HAVE_SYS_STAT_H) && (defined HAVE_LSTAT)) */
	/* can't stat - do nothing */
	return -1;
# endif /* (defined HAVE_SYS_STAT_H) && (defined HAVE_LSTAT) */

	/* save the current position and find the file size */
# if (defined HAVE_LONG_LONG) && (defined LSR_ANSIC)
	/* save the current position */
	pos = lseek64 ( fd, 0LL, SEEK_CUR );
	/* find the file size */
	size = lseek64 ( fd, 0LL, SEEK_END );
# else
	pos = lseek64 ( fd, 0, SEEK_CUR );
	size = lseek64 ( fd, 0, SEEK_END );
# endif

	lseek64 ( fd, pos, SEEK_SET );

	if ( (size == 0) || (length >= size) )
	{
		/* Nothing to do */
		return 0;
	}

	/* seeking to correct position */
	if ( lseek64 (fd, length, SEEK_SET) != length )
	{
		/* Unable to set current file position. */
		return -1;
	}


	if ( __lsr_sig_recvd () != 0 )
	{
		lseek64 ( fd, pos, SEEK_SET );
		return -1;
	}
	diff = (unsigned long long int)(size - length);
	nbuffers = diff/buffer_size;

	/* =========== Wiping loop ============== */
	if ( __lsr_set_signal_lock ( &fcntl_signal, fd, &fcntl_sig_old
# if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
		, &sa, &old_sa, &res_sig
# else
		, &sig_hndlr
# endif
		) != 0
	)
	{
		lseek64 ( fd, pos, SEEK_SET );
		return -1;
	}

# ifdef HAVE_MALLOC
	if ( diff < LSR_BUF_SIZE )
	{
		/* We know 'diff' < LSR_BUF_SIZE < ULONG_MAX here, so it's safe to cast */
		buf = (unsigned char *) malloc ( sizeof(unsigned char)*(unsigned long int) diff );
	}
# endif
	if ( (diff >= LSR_BUF_SIZE) || (buf == NULL) )
	{

# ifndef HAVE_MALLOC
		buf = __lsr_buffer;
# else /* HAVE_MALLOC */
		buf = (unsigned char *) malloc ( buffer_size );
		if ( buf == NULL )
		{
			/* Unable to get any memory. */
			lseek64 ( fd, pos, SEEK_SET );
			__lsr_unset_signal_unlock ( fcntl_signal, fd, fcntl_sig_old
# if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
				, &old_sa, res_sig
# else
				, &sig_hndlr
# endif
				);
			return -1;
		}
# endif /* ! HAVE_MALLOC */
		for ( j = 0; (j < npasses
# ifdef LAST_PASS_ZERO
			+1
# endif
			) && (__lsr_sig_recvd () == 0); j++ )
		{
# ifdef LAST_PASS_ZERO
			if ( j == npasses )
			{
				LSR_MEMSET (buf, 0, buffer_size);
				for ( i = 0; (i < nbuffers) && (__lsr_sig_recvd () == 0); i++ )
				{
					write_res = write (fd, buf, buffer_size);
					if ( write_res != (ssize_t)buffer_size )
					{
						break;
					}
				}
				write_len = sizeof(unsigned char)*((size_t) diff)%N_BYTES;
				write_res = write (fd, buf, write_len);
				if ( write_res != (ssize_t)write_len )
				{
					break;
				}

				/* this is the last pass and there was at
				  least one pass before - sync unconditionally */
				fsync (fd);
				break;
			}
# endif /* LAST_PASS_ZERO */
			__lsr_fill_buffer ( j, buf, buffer_size, selected );

			for ( i = 0; (i < nbuffers) && (__lsr_sig_recvd () == 0); i++ )
			{
				write_res = write (fd, buf, buffer_size);
				if ( write_res != (ssize_t)buffer_size )
				{
					break;
				}
			}
			write_len = sizeof(unsigned char)*((size_t) diff)%N_BYTES;
			write_res = write (fd, buf, write_len);
			if ( write_res != (ssize_t)write_len )
			{
				break;
			}

			if ( (npasses > 1)
# ifdef LAST_PASS_ZERO
				/* if LAST_PASS_ZERO is defined, there will be
				 one additionall pass with zeros, so sync no
				 matter how many passes there are declared: */
				|| (1 == 1)
# endif
				)
			{
				fsync (fd);
			}
			/* go back to the start position of writing */
			if ( lseek64 ( fd, length, SEEK_SET) != length )
			{
				/* Unable to set current file position. */
				break;
			}
		}
# ifdef HAVE_MALLOC
		free (buf);
# endif

	}
# ifdef HAVE_MALLOC
	else if ( buf != NULL )
	{

		for ( j = 0; (j < npasses
#  ifdef LAST_PASS_ZERO
			+1
#  endif
			) && (__lsr_sig_recvd () == 0); j++ )
		{
#  ifdef LAST_PASS_ZERO
			if ( j == npasses )
			{
				/* We know 'diff' < LSR_BUF_SIZE < ULONG_MAX here, so it's safe to cast */
				write_len = sizeof(unsigned char)*(unsigned long int)diff;
				LSR_MEMSET (buf, 0, write_len);
				write_res = write (fd, buf, write_len);
				if ( write_res != (ssize_t)write_len )
				{
					break;
				}

				/* this is the last pass and there was at
				  least one pass before - sync unconditionally */
				fsync (fd);
				break;
			}
#  endif /* LAST_PASS_ZERO */
			/* We know 'diff' < LSR_BUF_SIZE < ULONG_MAX here, so it's safe to cast */
			write_len = sizeof(unsigned char)*(unsigned long int)diff;
			__lsr_fill_buffer ( j, buf, write_len, selected );
			write_res = write (fd, buf, write_len);
			if ( write_res != (ssize_t)write_len )
			{
				break;
			}

			if ( (npasses > 1)
# ifdef LAST_PASS_ZERO
				/* if LAST_PASS_ZERO is defined, there will be
				 one additionall pass with zeros, so sync no
				 matter how many passes there are declared: */
				|| (1 == 1)
# endif
				)
			{
				fsync (fd);
			}
			/* go back to the start position of writing */
			if ( lseek64 (fd, length, SEEK_SET) != length )
			{
				/* Unable to set current file position. */
				break;
			}
		}
		free (buf);
	}
# endif /* HAVE_MALLOC */
	lseek64 ( fd, pos, SEEK_SET );
	__lsr_unset_signal_unlock ( fcntl_signal, fd, fcntl_sig_old
# if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
		, &old_sa, res_sig
# else
		, &sig_hndlr
# endif
		);
	return 0;
}
#endif	/* unistd.h */

/* ======================================================= */
