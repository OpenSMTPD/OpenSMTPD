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

#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>

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

static void
on_event(uint64_t id,  enum filter_hook event)
{
	printf("filter-event: id=%016"PRIx64", event=%s\n",
	    id, event_to_str(event));
}

static void
on_notify(uint64_t qid, enum filter_status status)
{
	printf("filter-notify: qid=%016"PRIx64", status=%s\n",
	    qid, status_to_str(status));
}

static void
on_connect(uint64_t id, uint64_t qid, struct filter_connect *conn)
{
	printf("filter-connect: id=%016"PRIx64", qid=%016"PRIx64" hostname=%s\n",
	    id, qid, conn->hostname);
	filter_api_accept_notify(qid);
}

static void
on_helo(uint64_t id, uint64_t qid, const char *helo)
{
	printf("filter: HELO id=%016"PRIx64", qid=%016"PRIx64" %s\n",
	    id, qid, helo);
	filter_api_accept_notify(qid);
}

static void
on_mail(uint64_t id, uint64_t qid, struct mailaddr *mail)
{
	printf("filter: MAIL id=%016"PRIx64", qid=%016"PRIx64" %s@%s\n",
	    id, qid, mail->user, mail->domain);
	filter_api_accept_notify(qid);
}

static void
on_rcpt(uint64_t id, uint64_t qid, struct mailaddr *rcpt)
{
	printf("filter: RCPT id=%016"PRIx64", qid=%016"PRIx64" %s@%s\n",
	    id, qid, rcpt->user, rcpt->domain);
	filter_api_accept_notify(qid);
}

static void
on_data(uint64_t id, uint64_t qid)
{
	printf("filter: DATA id=%016"PRIx64", qid=%016"PRIx64"\n", id, qid);
	filter_api_accept_notify(qid);
}

static void
on_dataline(uint64_t id, const char *data)
{
	printf("filter-data: id=%016"PRIx64", \"%s\"\n", id, data);
}

static void
on_eom(uint64_t id, uint64_t qid)
{
	printf("filter-eom: id=%016"PRIx64", qid=%016"PRIx64"\n", id, qid);
	filter_api_accept_notify(qid);
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

	filter_api_on_event(on_event);
	filter_api_on_notify(on_notify);
	filter_api_on_connect(on_connect);
	filter_api_on_helo(on_helo);
	filter_api_on_mail(on_mail);
	filter_api_on_rcpt(on_rcpt);
	filter_api_on_data(on_data);
	filter_api_on_dataline(on_dataline, 0);
	filter_api_on_eom(on_eom);
	filter_api_loop();

	log_debug("debug: filter-trace: exiting");

	return (1);
}
