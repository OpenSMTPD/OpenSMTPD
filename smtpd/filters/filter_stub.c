/*      $OpenBSD: table_sqlite.c,v 1.2 2013/01/31 18:34:43 eric Exp $   */

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

#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
        
#include "smtpd-defines.h"
#include "smtpd-api.h"
#include "log.h"

static void
on_connect(uint64_t id, uint64_t qid, struct filter_connect *conn)
{
	filter_api_accept(qid);
}

static void
on_helo(uint64_t id, uint64_t qid, const char *helo)
{
	filter_api_accept(qid);
}

static void
on_mail(uint64_t id, uint64_t qid, struct mailaddr *mail)
{
	filter_api_accept(qid);
}

static void
on_rcpt(uint64_t id, uint64_t qid, struct mailaddr *rcpt)
{
	filter_api_accept(qid);
}

static void
on_data(uint64_t id, uint64_t qid)
{
	filter_api_accept(qid);
}

static void
on_eom(uint64_t id, uint64_t qid)
{
	filter_api_accept(qid);
}

int
main(int argc, char **argv)
{
	int	ch;

	log_init(-1);

	while ((ch = getopt(argc, argv, "")) != -1) {
		switch (ch) {
		default:
			log_warnx("warn: filter-stub: bad option");
			return (1);
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;

	log_debug("debug: filter-stub: starting...");

	filter_api_on_connect(on_connect);
	filter_api_on_helo(on_helo);
	filter_api_on_mail(on_mail);
	filter_api_on_rcpt(on_rcpt);
	filter_api_on_data(on_data);
	filter_api_on_eom(on_eom);
	filter_api_loop();

	log_debug("debug: filter-stub: exiting");

	return (1);
}
