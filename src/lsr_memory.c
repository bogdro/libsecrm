/*
 * LibSecRm - A library for secure removing files.
 *	-- memory management functions' replacements.
 *
 * Copyright (C) 2007-2024 Bogdan Drozdowski, bogdro (at) users . sourceforge . net
 * Parts of this file are Copyright (C) Free Software Foundation, Inc.
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

#include "lsr_cfg.h"

#define _LARGEFILE64_SOURCE 1

#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif

#ifdef HAVE_MALLOC_H
# include <malloc.h>
#endif

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>	/* brk(), sbrk(), sysconf(), getpagesize() */
#endif

#include "lsr_priv.h"	/* includes intptr_t */

#if (!defined __STRICT_ANSI__) && (defined HAVE_SRANDOM) && (defined HAVE_RANDOM)
# define __lsr_rand random
#endif

/* This is for marking that we already are in memory allocation functions,
to avoid endless loops */
static volatile int __lsr_internal_function = 0;

#ifdef __cplusplus
extern "C" {
#endif

#ifndef HAVE_MEMALIGN
extern void *memalign LSR_PARAMS((size_t boundary, size_t size));
#endif
#ifndef HAVE_POSIX_MEMALIGN
extern int posix_memalign LSR_PARAMS((void **memptr, size_t alignment, size_t size));
#endif
/* aligned_alloc() on FreeBSD: disable POSIX, enable C11, but disable BSD and
 * X/Open which enable C99 and POSIX back. But since posix_memalign() requires
 * POSIX, we declare it manually.
 */
#if (!defined HAVE_ALIGNED_ALLOC) || (!defined __USE_GNU)
extern void *aligned_alloc LSR_PARAMS((size_t alignment, size_t size));
#endif

/* brk() and sbrk() on macOS: disable POSIX or set < 2001, but X/OPEN >= 700
 * sets it again to 2008xx. On FreeBSD: XOPEN <= 500 or BSD*** NOT defined.
 * Since we may need X/OPEN >= 700 and brk() and sbrk() seem to be deprecated
 * anyway, we just declare them manually here:
 */
#if (defined HAVE_BRK) && ( \
	(defined __DARWIN_C_ANSI) \
	|| (defined __DARWIN_C_FULL) \
	|| (defined __DARWIN_C_LEVEL) /* better than nothing */ \
	)
extern BRK_RETTYPE brk LSR_PARAMS((BRK_ARGTYPE end_data_segment));
#endif

#if (defined HAVE_SBRK) && ( \
	(defined __DARWIN_C_ANSI) \
	|| (defined __DARWIN_C_FULL) \
	|| (defined __DARWIN_C_LEVEL) /* better than nothing */ \
	)
extern SBRK_RETTYPE sbrk LSR_PARAMS((SBRK_ARGTYPE increment));
#endif

#ifdef __cplusplus
}
#endif

/* these defines allow checking the return type or parameter's type: */
#define const
#define int 1*
#define void 2
#define char 3

#ifdef LSR_BRK_RETTYPE_IS_POINTER
# undef LSR_BRK_RETTYPE_IS_POINTER
#endif
#if (BRK_RETTYPE 2 > 3)
# define LSR_BRK_RETTYPE_IS_POINTER 1
#endif

#ifdef LSR_SBRK_RETTYPE_IS_POINTER
# undef LSR_SBRK_RETTYPE_IS_POINTER
#endif
#if (SBRK_RETTYPE 2 > 3)
# define LSR_SBRK_RETTYPE_IS_POINTER 1
#endif

#undef int
#undef void
#undef char
#undef const

#ifdef TEST_COMPILE
# undef LSR_ANSIC
# if TEST_COMPILE > 1
#  undef HAVE_MALLOC
# endif
#endif

/* ======================================================= */
/**
 * Tells if we're in a libsecrm's internal function.
 */
int
__lsr_get_internal_function (LSR_VOID)
{
	return __lsr_internal_function;
}

/* ======================================================= */

/**
 * Sets whether we're in a libsecrm's internal function.
 */
void
__lsr_set_internal_function (
#ifdef LSR_ANSIC
	int is_intrn)
#else
	is_intrn)
	int is_intrn;
#endif
{
	__lsr_internal_function = is_intrn;
}

/* ======================================================= */
#ifdef LSR_INTERCEPT_MALLOC

void *
malloc (
#ifdef LSR_ANSIC
	size_t size)
#else
	size)
	size_t size;
#endif
{
	LSR_MAKE_ERRNO_VAR(err);
	void * ret;
	int selected[LSR_NPAT] = {0};

	__lsr_main ();
#ifdef LSR_DEBUG
	if ( __lsr_get_internal_function () == 0 )
	{
		__lsr_set_internal_function (1);
		fprintf (stderr, "libsecrm: malloc (%lu)\n", size);
		fflush (stderr);
		__lsr_set_internal_function (0);
	}
#endif

	if ( __lsr_real_malloc_location () == NULL )
	{
		LSR_SET_ERRNO_MISSING();
		return NULL;
	}
	if ( __lsr_get_internal_function () != 0 )
	{
		LSR_SET_ERRNO (err);
		return (*__lsr_real_malloc_location ()) ( size );
	}

	if ( __lsr_check_prog_ban () != 0 )
	{
		LSR_SET_ERRNO (err);
		return (*__lsr_real_malloc_location ()) ( size );
	}

	LSR_SET_ERRNO (err);
	ret = (*__lsr_real_malloc_location ()) ( size );
	if ( ret != NULL )
	{
		__lsr_fill_buffer ((unsigned int) __lsr_rand () % __lsr_get_npasses (),
			ret, size, selected);
	}
	return ret;
}
#endif
/* ======================================================= */

int
posix_memalign (
#ifdef LSR_ANSIC
	void **memptr, size_t alignment, size_t size)
#else
	memptr, alignment, size)
	void **memptr;
	size_t alignment;
	size_t size;
#endif
{
	LSR_MAKE_ERRNO_VAR(err);
	int ret;
	int selected[LSR_NPAT] = {0};

	__lsr_main ();
#ifdef LSR_DEBUG
	if ( __lsr_get_internal_function () == 0 )
	{
		__lsr_set_internal_function (1);
		fprintf (stderr, "libsecrm: posix_memalign (0x%lx, %lu, %lu)\n",
			(unsigned long int)memptr, alignment, size);
		fflush (stderr);
		__lsr_set_internal_function (0);
	}
#endif

	if ( __lsr_real_psx_memalign_loc () == NULL )
	{
		LSR_SET_ERRNO_MISSING();
		return -1;
	}
	if ( __lsr_get_internal_function () != 0 )
	{
		LSR_SET_ERRNO (err);
		return (*__lsr_real_psx_memalign_loc ()) ( memptr, alignment, size );
	}

	if ( memptr == NULL )
	{
		LSR_SET_ERRNO (err);
		return (*__lsr_real_psx_memalign_loc ()) ( memptr, alignment, size );
	}

	if ( __lsr_check_prog_ban () != 0 )
	{
		LSR_SET_ERRNO (err);
		return (*__lsr_real_psx_memalign_loc ()) ( memptr, alignment, size );
	}

	LSR_SET_ERRNO (err);
	ret = (*__lsr_real_psx_memalign_loc ()) ( memptr, alignment, size );
	if ( ret == 0 )
	{
		__lsr_fill_buffer ((unsigned int) __lsr_rand () % __lsr_get_npasses (),
			*memptr, size, selected);
	}
	return ret;
}

/* ======================================================= */

void *
valloc (
#ifdef LSR_ANSIC
	size_t size)
#else
	size)
	size_t size;
#endif
{
	LSR_MAKE_ERRNO_VAR(err);
	void *ret;
	int selected[LSR_NPAT] = {0};

	__lsr_main ();
#ifdef LSR_DEBUG
	if ( __lsr_get_internal_function () == 0 )
	{
		__lsr_set_internal_function (1);
		fprintf (stderr, "libsecrm: valloc (%lu)\n", size);
		fflush (stderr);
		__lsr_set_internal_function (0);
	}
#endif

	if ( __lsr_real_valloc_location () == NULL )
	{
		LSR_SET_ERRNO_MISSING();
		return NULL;
	}
	if ( __lsr_get_internal_function () != 0 )
	{
		LSR_SET_ERRNO (err);
		return (*__lsr_real_valloc_location ()) ( size );
	}

	if ( __lsr_check_prog_ban () != 0 )
	{
		LSR_SET_ERRNO (err);
		return (*__lsr_real_valloc_location ()) ( size );
	}

	LSR_SET_ERRNO (err);
	ret = (*__lsr_real_valloc_location ()) ( size );
	if ( ret != NULL )
	{
		__lsr_fill_buffer ((unsigned int) __lsr_rand () % __lsr_get_npasses (),
			ret, size, selected);
	}
	return ret;
}

/* ======================================================= */

#ifdef HAVE_PVALLOC

void *
pvalloc (
# ifdef LSR_ANSIC
	size_t size)
# else
	size)
	size_t size;
# endif
{
	LSR_MAKE_ERRNO_VAR(err);
	void *ret;
	int selected[LSR_NPAT] = {0};
	size_t to_wipe;

	__lsr_main ();
# ifdef LSR_DEBUG
	if ( __lsr_get_internal_function () == 0 )
	{
		__lsr_set_internal_function (1);
		fprintf (stderr, "libsecrm: pvalloc (%lu)\n", size);
		fflush (stderr);
		__lsr_set_internal_function (0);
	}
# endif

	if ( __lsr_real_pvalloc_location () == NULL )
	{
		LSR_SET_ERRNO_MISSING();
		return NULL;
	}
	if ( __lsr_get_internal_function () != 0 )
	{
		LSR_SET_ERRNO (err);
		return (*__lsr_real_pvalloc_location ()) ( size );
	}

	if ( __lsr_check_prog_ban () != 0 )
	{
		LSR_SET_ERRNO (err);
		return (*__lsr_real_pvalloc_location ()) ( size );
	}

	LSR_SET_ERRNO (err);
	ret = (*__lsr_real_pvalloc_location ()) ( size );
	if ( ret != NULL )
	{
		/* round up to the nearest page boundary */
# ifdef HAVE_SYSCONF
		to_wipe = (size_t)sysconf(_SC_PAGESIZE);
		to_wipe = ((size + to_wipe - 1) / to_wipe) * to_wipe;
# else
#  ifdef HAVE_GETPAGESIZE
		to_wipe = (size_t)getpagesize ();
		to_wipe = ((size + to_wipe - 1) / to_wipe) * to_wipe;
#  else
		to_wipe = size;
#  endif
# endif
		__lsr_fill_buffer ((unsigned int) __lsr_rand () % __lsr_get_npasses (),
			ret, to_wipe, selected);
	}
	return ret;
}
#endif /* HAVE_PVALLOC */

/* ======================================================= */

void *
memalign (
#ifdef LSR_ANSIC
	size_t boundary, size_t size)
#else
	boundary, size)
	size_t boundary;
	size_t size;
#endif
{
	LSR_MAKE_ERRNO_VAR(err);
	void *ret;
	int selected[LSR_NPAT] = {0};

	__lsr_main ();
#ifdef LSR_DEBUG
	if ( __lsr_get_internal_function () == 0 )
	{
		__lsr_set_internal_function (1);
		fprintf (stderr, "libsecrm: memalign (%lu, %lu)\n", boundary, size);
		fflush (stderr);
		__lsr_set_internal_function (0);
	}
#endif

	if ( __lsr_real_memalign_location () == NULL )
	{
		LSR_SET_ERRNO_MISSING();
		return NULL;
	}
	if ( __lsr_get_internal_function () != 0 )
	{
		LSR_SET_ERRNO (err);
		return (*__lsr_real_memalign_location ()) ( boundary, size );
	}

	if ( __lsr_check_prog_ban () != 0 )
	{
		LSR_SET_ERRNO (err);
		return (*__lsr_real_memalign_location ()) ( boundary, size );
	}

	LSR_SET_ERRNO (err);
	ret = (*__lsr_real_memalign_location ()) ( boundary, size );
	if ( ret != NULL )
	{
		__lsr_fill_buffer ((unsigned int) __lsr_rand () % __lsr_get_npasses (),
			ret, size, selected);
	}
	return ret;
}

/* ======================================================= */

#ifdef HAVE_ALIGNED_ALLOC

void *
aligned_alloc (
# ifdef LSR_ANSIC
	size_t alignment, size_t size)
# else
	alignment, size)
	size_t alignment;
	size_t size;
# endif
{
	LSR_MAKE_ERRNO_VAR(err);
	void *ret;
	int selected[LSR_NPAT] = {0};

	__lsr_main ();
# ifdef LSR_DEBUG
	if ( __lsr_get_internal_function () == 0 )
	{
		__lsr_set_internal_function (1);
		fprintf (stderr, "libsecrm: aligned_alloc (%lu, %lu)\n", alignment, size);
		fflush (stderr);
		__lsr_set_internal_function (0);
	}
# endif

	if ( __lsr_real_aligned_alloc_loc () == NULL )
	{
		LSR_SET_ERRNO_MISSING();
		return NULL;
	}
	if ( __lsr_get_internal_function () != 0 )
	{
		LSR_SET_ERRNO (err);
		return (*__lsr_real_aligned_alloc_loc ()) ( alignment, size );
	}

	if ( __lsr_check_prog_ban () != 0 )
	{
		LSR_SET_ERRNO (err);
		return (*__lsr_real_aligned_alloc_loc ()) ( alignment, size );
	}

	LSR_SET_ERRNO (err);
	ret = (*__lsr_real_aligned_alloc_loc ()) ( alignment, size );
	if ( ret != NULL )
	{
		__lsr_fill_buffer ((unsigned int) __lsr_rand () % __lsr_get_npasses (),
			ret, size, selected);
	}
	return ret;
}
#endif /* HAVE_ALIGNED_ALLOC */

/* ======================================================= */

BRK_RETTYPE
brk (
#ifdef LSR_ANSIC
	BRK_ARGTYPE end_data_segment)
#else
	end_data_segment)
	BRK_ARGTYPE end_data_segment;
#endif
{
	LSR_MAKE_ERRNO_VAR(err);
	BRK_RETTYPE ret;

#if (defined LSR_BRK_RETTYPE_IS_POINTER && defined LSR_SBRK_RETTYPE_IS_POINTER) \
	|| (!defined LSR_BRK_RETTYPE_IS_POINTER)
	SBRK_RETTYPE top;
	int selected[LSR_NPAT] = {0};
#endif

	__lsr_main ();
#ifdef LSR_DEBUG
	if ( __lsr_get_internal_function () == 0 )
	{
		__lsr_set_internal_function (1);
		fprintf (stderr, "libsecrm: brk (0x%lx)\n", (unsigned long int)end_data_segment);
		fflush (stderr);
		__lsr_set_internal_function (0);
	}
#endif

	if ( __lsr_real_brk_location () == NULL )
	{
		LSR_SET_ERRNO_MISSING();
#ifdef LSR_BRK_RETTYPE_IS_POINTER
		/* return type is a pointer (new program break) */
		return NULL;
#else
		/* return type is an integral type */
		return -1;
#endif
	}
	if ( __lsr_real_sbrk_location () == NULL )
	{
		/* we need sbrk(), so if it's not present, just leave */
		LSR_SET_ERRNO (err);
		return (*__lsr_real_brk_location ()) ( end_data_segment );
	}
	if ( __lsr_get_internal_function () != 0 )
	{
		LSR_SET_ERRNO (err);
		return (*__lsr_real_brk_location ()) ( end_data_segment );
	}

	if ( __lsr_check_prog_ban () != 0 )
	{
		LSR_SET_ERRNO (err);
		return (*__lsr_real_brk_location ()) ( end_data_segment );
	}

#ifdef LSR_BRK_RETTYPE_IS_POINTER
	/* return type is a pointer (new program break) */
# ifdef LSR_SBRK_RETTYPE_IS_POINTER
	/* sbrk() returns a pointer */
	top = (*__lsr_real_sbrk_location ()) ((SBRK_ARGTYPE)0);
	if ( end_data_segment > top )
	{
		/* allocation */
		LSR_SET_ERRNO (err);
		ret = (*__lsr_real_brk_location ()) ( end_data_segment );
		if ( ret != NULL )
		{
			__lsr_fill_buffer ((unsigned int) __lsr_rand () % __lsr_get_npasses (),
				(unsigned char *)top, (size_t) ((char *)ret-(char *)top), selected);
		}
	}
	else
	{
		/* deallocation */
		__lsr_fill_buffer ((unsigned int) __lsr_rand () % __lsr_get_npasses (),
			/* NOTE: OpenBSD uses "const char * end_data_segment", but we can't
			   pass "const" here, because the buffer is indeed modified. This is
			   not a problem, because the user is freeing this memory anyway. */
			(unsigned char *)end_data_segment,
			(size_t) ((char *)top-(const char *)end_data_segment), selected);
		LSR_SET_ERRNO (err);
		ret = (*__lsr_real_brk_location ()) ( end_data_segment );
	}
# else /* ! LSR_SBRK_RETTYPE_IS_POINTER */
	/* brk() returns a pointer, but sbrk() does not return a pointer.
	  Can't get the current program break, so don't wipe anything (don't know
	  how many bytes to wipe). */
	LSR_SET_ERRNO (err);
	ret = (*__lsr_real_brk_location ()) ( end_data_segment );
# endif /* LSR_SBRK_RETTYPE_IS_POINTER */
#else /* ! LSR_BRK_RETTYPE_IS_POINTER */
	/* return type is an integral type */
	top = (*__lsr_real_sbrk_location ()) ((SBRK_ARGTYPE)0);
	/* wipe the memory first if freeing */
	if ( end_data_segment > top )
	{
		/* allocation */
		LSR_SET_ERRNO (err);
		ret = (*__lsr_real_brk_location ()) ( end_data_segment );
		if ( ret == 0 )
		{
			__lsr_fill_buffer ((unsigned int) __lsr_rand () % __lsr_get_npasses (),
				(unsigned char *)top, (size_t) ((const char *)end_data_segment-(char *)top),
				selected);
		}
	}
	else
	{
		/* deallocation */
		__lsr_fill_buffer ((unsigned int) __lsr_rand () % __lsr_get_npasses (),
			(unsigned char *)end_data_segment,
			(size_t) ((char *)top-(const char *)end_data_segment), selected);
		LSR_SET_ERRNO (err);
		ret = (*__lsr_real_brk_location ()) ( end_data_segment );
	}
#endif /* LSR_BRK_RETTYPE_IS_POINTER */

	return ret;
}

/* ======================================================= */

SBRK_RETTYPE
sbrk (
#ifdef LSR_ANSIC
	SBRK_ARGTYPE increment)
#else
	increment)
	SBRK_ARGTYPE increment;
#endif
{
	LSR_MAKE_ERRNO_VAR(err);
	SBRK_RETTYPE ret;

#if (defined LSR_SBRK_RETTYPE_IS_POINTER) || \
	((!defined LSR_SBRK_RETTYPE_IS_POINTER) && (defined LSR_BRK_RETTYPE_IS_POINTER))
	int selected[LSR_NPAT] = {0};
#endif

#if (!defined LSR_SBRK_RETTYPE_IS_POINTER) && (defined LSR_BRK_RETTYPE_IS_POINTER)
	void * top;
#endif

	__lsr_main ();
#ifdef LSR_DEBUG
	if ( __lsr_get_internal_function () == 0 )
	{
		__lsr_set_internal_function (1);
		fprintf (stderr, "libsecrm: sbrk (%d)\n", (int)increment);
		fflush (stderr);
		__lsr_set_internal_function (0);
	}
#endif

	if ( __lsr_real_sbrk_location () == NULL )
	{
		LSR_SET_ERRNO_MISSING();
		return NULL;
	}
	if ( __lsr_get_internal_function () != 0 )
	{
		LSR_SET_ERRNO (err);
		return (*__lsr_real_sbrk_location ()) ( increment );
	}

	if ( __lsr_check_prog_ban () != 0 )
	{
		LSR_SET_ERRNO (err);
		return (*__lsr_real_sbrk_location ()) ( increment );
	}

	LSR_SET_ERRNO (err);
	ret = (*__lsr_real_sbrk_location ()) ( increment );

#if LSR_SBRK_RETTYPE_IS_POINTER
	/* return type is a pointer */
	if ( (ret != NULL) && ((long int) ret != -1) )
	{
		if ( increment > 0 )
		{
			__lsr_fill_buffer ((unsigned int) __lsr_rand () % __lsr_get_npasses (),
				(unsigned char *)ret, (size_t) increment, selected);
		}
		else if ( increment < 0 )
		{
			__lsr_fill_buffer ((unsigned int) __lsr_rand () % __lsr_get_npasses (),
				(unsigned char *)ret-increment, (size_t) (-increment), selected);
		}
	}
#else /* !LSR_SBRK_RETTYPE_IS_POINTER */
	/* return type is an integral type. Get the current top first. */
# if LSR_BRK_RETTYPE_IS_POINTER
	/* return type of brk() must be a pointer to get the current top */
	if ( (__lsr_real_brk_location () != NULL) && (ret == 0) )
	{
		LSR_GET_ERRNO (err);
		top = (*__lsr_real_brk_location ()) ((BRK_ARGTYPE)0);
		LSR_SET_ERRNO (err);
		if ( (top != NULL) && ((int) top != -1) )
		{
			if ( increment > 0 )
			{
				__lsr_fill_buffer ((unsigned int) __lsr_rand () % __lsr_get_npasses (),
					(unsigned char *)top, (size_t) increment, selected);
			}
			else if ( increment < 0 )
			{
				__lsr_fill_buffer ((unsigned int) __lsr_rand () % __lsr_get_npasses (),
					(unsigned char *)top-increment, (size_t)(-increment), selected);
			}
		}
	}
# else /* ! LSR_BRK_RETTYPE_IS_POINTER */
	/* return type of brk() is not a pointer - we can't do anything */
# endif /* LSR_BRK_RETTYPE_IS_POINTER */
#endif /* LSR_SBRK_RETTYPE_IS_POINTER */

	return ret;
}
