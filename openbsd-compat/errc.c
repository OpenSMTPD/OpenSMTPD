/*
 * Copyright (c) 2023 Omar Polo <op@openbsd.org>
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

#include "includes.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void
vwarn(const char *fmt, va_list ap)
{
	int save_errno;

	save_errno = errno;

	fprintf(stderr, "%s: ", getprogname());
	if (fmt != NULL) {
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, ": ");
	}
	fprintf(stderr, "%s\n", strerror(save_errno));

	errno = save_errno;
}

void
vwarnc(int code, const char *fmt, va_list ap)
{
	errno = code;
	vwarn(fmt, ap);
}

void
vwarnx(const char *fmt, va_list ap)
{
	int save_errno;

	save_errno = errno;

	fprintf(stderr, "%s: ", getprogname());
	if (fmt != NULL)
		vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);

	errno = save_errno;
}

__dead void
verr(int eval, const char *fmt, va_list ap)
{
	vwarn(fmt, ap);
	exit(eval);
}

__dead void
verrc(int eval, int code, const char *fmt, va_list ap)
{
	vwarnc(code, fmt, ap);
	exit(eval);
}

__dead void
verrx(int eval, const char *fmt, va_list ap)
{
	vwarnx(fmt, ap);
	exit(eval);
}

__dead void
err(int eval, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	verr(eval, fmt, ap);
	va_end(ap);
}

__dead void
errc(int eval, int code, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	verrc(eval, code, fmt, ap);
	va_end(ap);
}

__dead void
errx(int eval, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	verrx(eval, fmt, ap);
	va_end(ap);
}

void
warn(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vwarn(fmt, ap);
	va_end(ap);
}

void
warnc(int code, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vwarnc(code, fmt, ap);
	va_end(ap);
}

void
warnx(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vwarnx(fmt, ap);
	va_end(ap);
}
