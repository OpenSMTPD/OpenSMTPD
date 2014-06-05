/*	$OpenBSD$	*/

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

#include "includes.h"

#include <sys/types.h>

#include <unistd.h>

#include "smtpd-defines.h"
#include "smtpd-api.h"
#include "log.h"

static int table_stub_update(void);
static int table_stub_check(int, const char *);
static int table_stub_lookup(int, const char *, char *, size_t);
static int table_stub_fetch(int, char *, size_t);

int
main(int argc, char **argv)
{
	int	ch;

	log_init(1);

	while ((ch = getopt(argc, argv, "")) != -1) {
		switch (ch) {
		default:
			log_warnx("warn: table-stub: bad option");
			return (1);
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 0) {
		log_warnx("warn: table-stub: bogus argument(s)");
		return (1);
	}

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
