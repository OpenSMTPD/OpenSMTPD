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

#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>

#include "smtpd-defines.h"
#include "smtpd-api.h"
#include "log.h"

static const char *
event_to_str(int hook)
{
	switch (hook) {
	case HOOK_RESET:
		return "RESET";
	case HOOK_DISCONNECT:
		return "DISCONNECT";
	case HOOK_COMMIT:
		return "COMMIT";
	case HOOK_ROLLBACK:
		return "ROLLBACK";
	default:
		return "???";
	}
}

static const char *
status_to_str(int status)
{
	switch (status) {
	case FILTER_OK:
		return "OK";
	case FILTER_FAIL:
		return "FAIL";
	case FILTER_CLOSE:
		return "CLOSE";
	default:
		return "???";
	}
}

static int
on_connect(uint64_t id, struct filter_connect *conn)
{
	printf("filter-trace: id=%016"PRIx64", hostname=%s\n",
	    id, conn->hostname);
	return filter_api_accept(id);
}

static int
on_helo(uint64_t id, const char *helo)
{
	printf("filter-trace: HELO id=%016"PRIx64", %s\n", id, helo);
	return filter_api_accept(id);
}

static int
on_mail(uint64_t id, struct mailaddr *mail)
{
	printf("filter-trace: MAIL id=%016"PRIx64", %s@%s\n",
	    id, mail->user, mail->domain);
	return filter_api_accept(id);
}

static int
on_rcpt(uint64_t id, struct mailaddr *rcpt)
{
	printf("filter-trace: RCPT id=%016"PRIx64", %s@%s\n",
	    id, rcpt->user, rcpt->domain);
	return filter_api_accept(id);
}

static int
on_data(uint64_t id)
{
	printf("filter-trace: RCPT id=%016"PRIx64, id);
	return filter_api_accept(id);
}

static int
on_eom(uint64_t id, size_t size)
{
	printf("filter-trace: EOM id=%016"PRIx64", size=%zu", id, size);
	return filter_api_accept(id);
}

static void
on_dataline(uint64_t id, const char *line)
{
	printf("filter-trace: [dataline] id=%016"PRIx64", \"%s\"\n", id, line);
	filter_api_writeln(id, line);
}

int
main(int argc, char **argv)
{
	int	ch;

	log_init(-1);

	while ((ch = getopt(argc, argv, "")) != -1) {
		switch (ch) {
		default:
			log_warnx("warn: filter-trace: bad option");
			return (1);
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;

	log_debug("debug: filter-trace: starting...");

	filter_api_on_connect(on_connect);
	filter_api_on_helo(on_helo);
	filter_api_on_mail(on_mail);
	filter_api_on_rcpt(on_rcpt);
	filter_api_on_data(on_data);
	filter_api_on_dataline(on_dataline);
	filter_api_on_eom(on_eom);
	filter_api_loop();

	log_debug("debug: filter-trace: exiting");

	return (1);
}
