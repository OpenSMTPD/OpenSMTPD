/*	$OpenBSD: table_sqlite.c,v 1.2 2013/01/31 18:34:43 eric Exp $	*/

/*
 * Copyright (c) 2013 Eric Faurot <eric@openbsd.org>
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

#include <sys/types.h>

#include <err.h>
#include <getopt.h>

#include "smtpd-defines.h"
#include "smtpd-api.h"

static int table_stub_update(void);
static int table_stub_check(int, const char *);
static int table_stub_lookup(int, const char *, char *, size_t);
static int table_stub_fetch(int, char *, size_t);

int
main(int argc, char **argv)
{
	int	ch;

	while ((ch = getopt(argc, argv, "f:")) != -1) {
		switch (ch) {
		default:
			errx(1, "bad option");
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;

	table_api_on_update(table_stub_update);
	table_api_on_check(table_stub_check);
	table_api_on_lookup(table_stub_lookup);
	table_api_on_fetch(table_stub_fetch);
	table_api_dispatch();

	return (0);
}

static int
table_stub_update(void)
{
	return (-1);
}

static int
table_stub_check(int service, const char *key)
{
	return (-1);
}

static int
table_stub_lookup(int service, const char *key, char *dst, size_t sz)
{
	return (-1);
}

static int
table_stub_fetch(int service, char *dst, size_t sz)
{
	return (-1);
}
