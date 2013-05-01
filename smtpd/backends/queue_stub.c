/*	$OpenBSD: filter_api.c,v 1.4 2012/08/19 14:16:58 chl Exp $	*/

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
#include <stdlib.h>

#include "smtpd-defines.h"
#include "smtpd-api.h"
#include "log.h"

static int
queue_stub_message_create(uint32_t *msgid)
{
	return (0);
}

static int
queue_stub_message_commit(uint32_t msgid)
{
	return (0);
}

static int
queue_stub_message_delete(uint32_t msgid)
{
	return (0);
}

static int
queue_stub_message_fd_r(uint32_t msgid)
{
	return (-1);
}

static int
queue_stub_message_fd_w(uint32_t msgid)
{
	return (-1);
}

static int
queue_stub_message_corrupt(uint32_t msgid)
{
	return (0);
}

static int
queue_stub_envelope_create(uint32_t msgid, const char *buf, size_t len,
    uint64_t *evpid)
{
	return (0);
}

static int
queue_stub_envelope_delete(uint64_t evpid)
{
	return (0);
}

static int
queue_stub_envelope_update(uint64_t evpid, const char *buf, size_t len)
{
	return (0);
}

static int
queue_stub_envelope_load(uint64_t evpid, char *buf, size_t len)
{
	return (0);
}

static int
queue_stub_envelope_walk(uint64_t *evpid)
{
	return (0);
}

int
main(int argc, char **argv)
{
	int	ch;

	log_init(1);

	while ((ch = getopt(argc, argv, "f:")) != -1) {
		switch (ch) {
		default:
			log_warnx("warn: backend-queue-stub: bad option");
			exit(1);
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;

	queue_api_on_message_create(queue_stub_message_create);
	queue_api_on_message_commit(queue_stub_message_commit);
	queue_api_on_message_delete(queue_stub_message_delete);
	queue_api_on_message_fd_r(queue_stub_message_fd_r);
	queue_api_on_message_fd_w(queue_stub_message_fd_w);
	queue_api_on_message_corrupt(queue_stub_message_corrupt);
	queue_api_on_envelope_create(queue_stub_envelope_create);
	queue_api_on_envelope_delete(queue_stub_envelope_delete);
	queue_api_on_envelope_update(queue_stub_envelope_update);
	queue_api_on_envelope_load(queue_stub_envelope_load);
	queue_api_on_envelope_walk(queue_stub_envelope_walk);

	queue_api_dispatch();

	return (0);
}
