/*
 * A library for secure removing files.
 *	-- file deleting (removing, unlinking) functions' replacements.
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

#include "lsr_cfg.h"
#define _GNU_SOURCE	1	/* need F_SETLEASE */

#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#else
# define O_WRONLY	1
# define O_RDWR		2
#endif

#ifndef O_EXCL
# define O_EXCL		0200
#endif

#ifdef HAVE_STRING_H
# if (!STDC_HEADERS) && (defined HAVE_MEMORY_H)
#  include <memory.h>
# endif
# include <string.h>
#endif

#ifdef LSR_DEBUG
# include <stdio.h>
#endif

#ifdef HAVE_MALLOC_H
# include <malloc.h>
#endif

#ifdef HAVE_STDLIB_H
# include <stdlib.h>	/* random(), rand()  */
#endif

#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif

#ifdef HAVE_LIBGEN_H
# include <libgen.h>
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#include "libsecrm-priv.h"

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
# ifndef truncate
#  pragma GCC poison truncate
# endif
# ifndef ftruncate
#  pragma GCC poison ftruncate
# endif
# ifndef truncate64
#  pragma GCC poison truncate64
# endif
# ifndef ftruncate64
#  pragma GCC poison ftruncate64
# endif
#endif

/* ======================================================= */
/**
 * Renames the given file using rename() or renameat(). The return value is
 * the "last new name" and MUST be free()d unless *free_new == 0.
 */
static char * LSR_ATTR ((nonnull))
__lsr_rename (
# if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	const char * const name, const int use_renameat
# ifndef HAVE_RENAMEAT
	LSR_ATTR ((unused))
# endif
	, const int renameat_fd
# ifndef HAVE_RENAMEAT
	LSR_ATTR ((unused))
# endif
	, int * const free_new )
#else
	name, use_renameat
# ifndef HAVE_RENAMEAT
	LSR_ATTR ((unused))
# endif
	, renameat_fd
# ifndef HAVE_RENAMEAT
	LSR_ATTR ((unused))
# endif
	, free_new )
	const char * const name;
	const int use_renameat
# ifndef HAVE_RENAMEAT
	LSR_ATTR ((unused))
# endif
	;
	const int renameat_fd
# ifndef HAVE_RENAMEAT
	LSR_ATTR ((unused))
# endif
	;
	int * const free_new;
#endif
{
	char *old_name, *new_name;
	const char *base_name;
	unsigned int i, j, rnd;
	int diff;
	size_t base_len;
	const size_t name_len = strlen (name);
	char repl;

	*free_new = 0;
	new_name = (char *) malloc ( name_len + 1 );
	if ( new_name == NULL )
	{
		return NULL;
	}

	old_name = (char *) malloc ( name_len + 1 );
	if ( old_name == NULL )
	{
		free (new_name);
		return NULL;
	}
	*free_new = 1;
#ifdef HAVE_STRING_H
	strncpy (new_name, name, name_len + 1);
#else
# if defined HAVE_MEMCPY
	memcpy (new_name, name, name_len + 1);
# else
	for ( i=0; i < name_len + 1; i++ )
	{
		new_name[i] = name[i];
	}
# endif
#endif
	new_name[name_len] = '\0';

#ifdef HAVE_LIBGEN_H
	base_name = strstr ( name, basename (new_name) );
	/* basename() may modify its parameter, so set it back again. */
# ifdef HAVE_STRING_H
	strncpy (new_name, name, name_len + 1);
# else
#  if defined HAVE_MEMCPY
	memcpy (new_name, name, name_len + 1);
#  else
	for ( i=0; i < name_len + 1; i++ )
	{
		new_name[i] = name[i];
	}
#  endif
# endif
	new_name[name_len] = '\0';
#else
	base_name = rindex ( name, (int)'/' );
#endif
	if ( base_name == NULL )
	{
		base_len = name_len;
		base_name = name;
	}
	else
	{
		base_len = strlen (base_name);
	}
	old_name[name_len] = '\0';

	diff = name_len - base_len;
	for ( i=0; i < npasses; i++ )
	{
#if (!defined __STRICT_ANSI__) && (defined HAVE_RANDOM)
		rnd = (unsigned) random ();
#else
		rnd = (unsigned) rand ();
#endif
		repl = (char) ('A'+(rnd%26));
#ifdef HAVE_STRING_H
		strncpy (old_name, new_name, name_len + 1);
#else
# if defined HAVE_MEMCPY
		memcpy (old_name, new_name, name_len + 1);
# else
		for ( i=0; i < name_len + 1; i++ )
		{
			old_name[i] = new_name[i];
		}
# endif
#endif

		for ( j=0; j < base_len; j++ )
		{
			new_name[j+diff] = repl;
		}
#ifdef HAVE_RENAMEAT
		if ( (use_renameat != 0) && (renameat_fd > 0) )
		{
			renameat ( renameat_fd, old_name, renameat_fd, new_name );
		}
		else
#endif
		{
			rename (old_name, new_name);
		}

#if (!defined __STRICT_ANSI__) && (defined HAVE_UNISTD_H)
		if ( npasses > 1 )
		{
			sync();
		}
#endif
	}
	free (old_name);
	return new_name;
}

/* ======================================================= */

int
unlink (
# if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	const char * const name)
#else
	name)
	const char * const name;
#endif
{
# if (defined __GNUC__) && (!defined unlink)
# pragma GCC poison unlink
#endif
	int free_new, fd, res;
	char *new_name;

#ifdef HAVE_SYS_STAT_H
	struct stat64 s;
#endif

#ifdef HAVE_ERRNO_H
	int err = 0;
#endif

# ifdef HAVE_SIGNAL_H
	int res_sig;
	int fcntl_signal, fcntl_sig_old;
#  if (!defined HAVE_SIGACTION) || (defined __STRICT_ANSI__)
	sighandler_t sig_hndlr;
#  else
	struct sigaction sa, old_sa;
#  endif
# endif

	__lsr_main ();
#ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: unlink(%s)\n", (name==NULL)? "null" : name);
	fflush (stderr);
#endif

	if ( __lsr_real_unlink == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = ENOSYS;
#endif
		return -1;
	}

	if ( (__lsr_check_prog_ban () != 0) || (__lsr_check_file_ban (name) != 0) )
	{
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		return (*__lsr_real_unlink) (name);
	}

	if ( name == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_unlink) (name);
	}

	/* The ".ICEauthority" part is a workaround an issue with Kate and DCOP.
	   The sh-thd is a workaround an issue with BASH and here-documents.
	 */
	if ( (strlen (name) == 0) || (strstr (name, ".ICEauthority") != NULL)
		|| (strstr (name, "sh-thd-") != NULL) || (strstr (name, "libsecrm") != NULL)
	   )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_unlink) (name);
	}

#if (!defined HAVE_SYS_STAT_H) || (!defined HAVE_LSTAT)
	/* Sorry, can't truncate something I can't lstat(). This would cause problems. */
	/*
	   NOTE: the old name should be preserved. If unlink() fails, the calling program
	   might want to do something else with the object and probably expects to
	   find its old name.
	*/
# ifdef HAVE_ERRNO_H
	errno = err;
# endif
	return (*__lsr_real_unlink) (name);
#else
	/* NOTE: stat() may be dangerous. If a filesystem has symbolic links, but lstat()
	   is unavailable, stat() returns information about the target of the link.
	   The link itself will be removed, but it's the target of the link
	   that will be wiped. This is why we either use lstat() or quit.
	*/
	if ( lstat64 (name, &s) == 0 )
	{
		/* don't operate on non-files */
		if ( !S_ISREG (s.st_mode) )
		{
# ifdef HAVE_ERRNO_H
			errno = err;
# endif
			return (*__lsr_real_unlink) (name);
		}
	}
	else
	{
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		return (*__lsr_real_unlink) (name);
	}

	if ( __lsr_real_open != NULL )
	{
		fd = (*__lsr_real_open) (name, O_WRONLY|O_EXCL);
		if ( fd > 0 )
		{
			if ( __lsr_set_signal_lock ( &fcntl_signal, fd, &fcntl_sig_old
#if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
				, &sa, &old_sa, &res_sig
#else
				, &sig_hndlr
#endif
				) == 0
			)
			{
#ifdef LSR_DEBUG
				fprintf (stderr, "libsecrm: unlink(): wiping %s\n", name);
				fflush (stderr);
#endif
#if (defined HAVE_LONG_LONG) && ( \
	defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)	\
	)
				__lsr_fd_truncate ( fd, 0LL );
#else
				__lsr_fd_truncate ( fd, (off64_t)0 );
#endif
				__lsr_unset_signal_unlock ( fcntl_signal, fd, fcntl_sig_old
#if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
					, &old_sa, res_sig
#else
					, &sig_hndlr
#endif
					);
			}
			close (fd);
		}
	}

	new_name = __lsr_rename ( name, 0, -1, &free_new );

# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	if ( new_name == NULL )
	{
		res = (*__lsr_real_unlink) (name);
	}
	else
	{
		res = (*__lsr_real_unlink) (new_name);
	}
# ifdef HAVE_ERRNO_H
	err = errno;
# endif
	if ( free_new != 0 )
	{
		free (new_name);
	}
# ifdef HAVE_ERRNO_H
	errno = err;
# endif
	return res;

#endif	/* stat.h */
}

/* ======================================================= */

int
unlinkat (
# if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	const int dirfd, const char * const name, const int flags)
#else
	dirfd, name, flags)
	const int dirfd;
	const char * const name;
	const int flags;
#endif
{
# if (defined __GNUC__) && (!defined unlinkat)
# pragma GCC poison unlinkat
#endif

	int free_new, fd, res;
	char *new_name;

#ifdef HAVE_SYS_STAT_H
	struct stat64 s;
#endif

#ifdef HAVE_ERRNO_H
	int err = 0;
#endif

# ifdef HAVE_SIGNAL_H
	int res_sig;
	int fcntl_signal, fcntl_sig_old;
#  if (!defined HAVE_SIGACTION) || (defined __STRICT_ANSI__)
	sighandler_t sig_hndlr;
#  else
	struct sigaction sa, old_sa;
#  endif
# endif

	__lsr_main ();
#ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: unlinkat(%d, %s, %d)\n", dirfd, (name==NULL)? "null" : name, flags);
	fflush (stderr);
#endif

	if ( __lsr_real_unlinkat == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = ENOSYS;
#endif
		return -1;
	}

	if ( (__lsr_check_prog_ban () != 0) || (__lsr_check_file_ban (name) != 0) )
	{
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		return (*__lsr_real_unlinkat) (dirfd, name, flags);
	}

	if ( name == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_unlinkat) (dirfd, name, flags);
	}

	if ( (strlen (name) == 0) || (strstr (name, ".ICEauthority") != NULL)
		|| (strstr (name, "sh-thd-") != NULL) || (strstr (name, "libsecrm") != NULL)
	   )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_unlinkat) (dirfd, name, flags);
	}

#ifdef HAVE_ERRNO_H
	errno = 0;
#endif
	fd = (*__lsr_real_openat) (dirfd, name, O_WRONLY);
	if ( (fd < 0)
#ifdef HAVE_ERRNO_H
		|| (errno != 0)
#endif
	   )
	{
#ifdef HAVE_UNISTD_H
		if ( fd > 0 ) close (fd);
#endif
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_unlinkat) (dirfd, name, flags);
	}

#if (!defined HAVE_SYS_STAT_H) || (!defined HAVE_FSTAT)
	/* Sorry, can't truncate something I can't fstat. This would cause problems */
	close (fd);
# ifdef HAVE_ERRNO_H
	errno = err;
# endif
	return (*__lsr_real_unlinkat) (dirfd, name, flags);
#else
	if ( fstat64 (fd, &s) == 0 )
	{
		/* don't operate on non-files */
		if ( !S_ISREG (s.st_mode) )
		{
# ifdef HAVE_ERRNO_H
			errno = err;
# endif
			return (*__lsr_real_unlinkat) (dirfd, name, flags);
		}
	}
	else
	{
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		return (*__lsr_real_unlinkat) (dirfd, name, flags);
	}

#  ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: unlinkat(): wiping %s\n", name);
	fflush (stderr);
#  endif

	if ( __lsr_set_signal_lock ( &fcntl_signal, fd, &fcntl_sig_old
#if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
		, &sa, &old_sa, &res_sig
#else
		, &sig_hndlr
#endif
		) == 0
	)
	{
#   if (defined HAVE_LONG_LONG) && ( \
	defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)	\
	)
		__lsr_fd_truncate ( fd, 0LL );
#   else
		__lsr_fd_truncate ( fd, (off64_t)0 );
#   endif
		__lsr_unset_signal_unlock ( fcntl_signal, fd, fcntl_sig_old
#if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
			, &old_sa, res_sig
#else
			, &sig_hndlr
#endif
			);
	}
# ifdef HAVE_UNISTD_H
	close (fd);
# endif

	new_name = __lsr_rename ( name, 1, dirfd, &free_new );

# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	if ( new_name == NULL )
	{
		res = (*__lsr_real_unlinkat) (dirfd, name, flags);
	}
	else
	{
		res = (*__lsr_real_unlinkat) (dirfd, new_name, flags);
	}
# ifdef HAVE_ERRNO_H
	err = errno;
# endif
	if ( free_new != 0 )
	{
		free (new_name);
	}
# ifdef HAVE_ERRNO_H
	errno = err;
# endif
	return res;

#endif	/* stat.h */
}

/* ======================================================= */

int
remove (
# if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	const char * const name)
#else
	name)
	const char * const name;
#endif
{
# if (defined __GNUC__) && (!defined remove)
# pragma GCC poison remove
#endif

	int free_new, fd, res;
	char *new_name;

#ifdef HAVE_SYS_STAT_H
	struct stat64 s;
#endif

#ifdef HAVE_ERRNO_H
	int err = 0;
#endif

# ifdef HAVE_SIGNAL_H
	int res_sig;
	int fcntl_signal, fcntl_sig_old;
#  if (!defined HAVE_SIGACTION) || (defined __STRICT_ANSI__)
	sighandler_t sig_hndlr;
#  else
	struct sigaction sa, old_sa;
#  endif
# endif

	__lsr_main ();
#ifdef LSR_DEBUG
	fprintf (stderr, "libsecrm: remove(%s)\n", (name==NULL)? "null" : name);
	fflush (stderr);
#endif

	if ( __lsr_real_remove == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = ENOSYS;
#endif
		return -1;
	}

	if ( (__lsr_check_prog_ban () != 0) || (__lsr_check_file_ban (name) != 0) )
	{
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		return (*__lsr_real_remove) (name);
	}

	if ( name == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_remove) (name);
	}

	if ( (strlen (name) == 0) || (strstr (name, ".ICEauthority") != NULL)
		|| (strstr (name, "sh-thd-") != NULL) || (strstr (name, "libsecrm") != NULL)
	   )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_remove) (name);
	}

#if (!defined HAVE_SYS_STAT_H) || (!defined HAVE_LSTAT)
	/* Sorry, can't truncate something I can't lstat(). This would cause problems.
	   See unlink() above. */
# ifdef HAVE_ERRNO_H
	errno = err;
# endif
	return (*__lsr_real_remove) (name);
#else
	if ( lstat64 (name, &s) == 0 )
	{
		/* don't operate on non-files */
		if ( !S_ISREG (s.st_mode) )
		{
# ifdef HAVE_ERRNO_H
			errno = err;
# endif
			return (*__lsr_real_remove) (name);
		}
	}
	else
	{
# ifdef HAVE_ERRNO_H
		errno = err;
# endif
		return (*__lsr_real_remove) (name);
	}

	if ( __lsr_real_open != NULL )
	{
		fd = (*__lsr_real_open) (name, O_WRONLY|O_EXCL);
		if ( fd > 0 )
		{
			if ( __lsr_set_signal_lock ( &fcntl_signal, fd, &fcntl_sig_old
#if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
				, &sa, &old_sa, &res_sig
#else
				, &sig_hndlr
#endif
				) == 0
			)
			{
#  ifdef LSR_DEBUG
				fprintf (stderr, "libsecrm: remove(): wiping %s\n", name);
				fflush (stderr);
#  endif
#  ifdef HAVE_UNISTD_H
#   if (defined HAVE_LONG_LONG) && ( \
	defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)	\
	)
				__lsr_fd_truncate ( fd, 0LL );
#   else
				__lsr_fd_truncate ( fd, (off64_t)0 );
#   endif
#  endif
				__lsr_unset_signal_unlock ( fcntl_signal, fd, fcntl_sig_old
#if (defined HAVE_SIGACTION) && (!defined __STRICT_ANSI__)
					, &old_sa, res_sig
#else
					, &sig_hndlr
#endif
					);
			}
			close (fd);
		}	/* fd > 0 */
	} /* __real_open */

	new_name = __lsr_rename ( name, 0, -1, &free_new );

# ifdef HAVE_ERRNO_H
	errno = 0;
# endif
	if ( new_name == NULL )
	{
		res = (*__lsr_real_remove) (name);
	}
	else
	{
		res = (*__lsr_real_remove) (new_name);
	}
# ifdef HAVE_ERRNO_H
	err = errno;
# endif
	if ( free_new != 0 )
	{
		free (new_name);
	}
# ifdef HAVE_ERRNO_H
	errno = err;
# endif
	return res;

#endif	/* stat.h */
}
