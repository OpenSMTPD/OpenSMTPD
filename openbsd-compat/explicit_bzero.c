/*  $OpenBSD: explicit_bzero.c,v 1.4 2015/08/31 02:53:57 guenther Exp $ */
/*
 * Public domain.
 * Written by Matthew Dempsky.
 */

#include "includes.h"
#ifndef HAVE_EXPLICIT_BZERO

#include <string.h>

void
explicit_bzero(void *buf, size_t len)
{
	memset(buf, 0, len);
}
#endif
