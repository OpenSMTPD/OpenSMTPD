/*	$OpenBSD: basename.c,v 1.14 2005/08/08 08:05:33 espie Exp $	*/

/*
 * Copyright (c) 1997, 2004 Todd C. Miller <Todd.Miller@courtesan.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* OPENBSD ORIGINAL: lib/libc/gen/errc.c */

#include "includes.h"

#ifndef HAVE_ERRC

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern char *__progname;

static void
_verrc(int eval, int code, const char *fmt, va_list ap)
{
        (void)fprintf(stderr, "%s: ", __progname);
        if (fmt != NULL) {
                (void)vfprintf(stderr, fmt, ap);
                (void)fprintf(stderr, ": ");
        }
        (void)fprintf(stderr, "%s\n", strerror(code));
        exit(eval);
}

void
errc(int eval, int code, const char *fmt, ...)
{
        va_list ap;

        va_start(ap, fmt);
        _verrc(eval, code, fmt, ap);
        va_end(ap);
}

#endif
