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

#include <sys/types.h>

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include "smtpd-defines.h"
#include "smtpd-api.h"
#include "log.h"
#include "queue_utils.h"

static int
queue_null_message_create(uint32_t *msgid)
{
	*msgid = queue_generate_msgid();
	return (1);
}

static int
queue_null_message_commit(uint32_t msgid, const char *path)
{
	return (1);
}

static int
queue_null_message_delete(uint32_t msgid)
{
	return (1);
}

static int
queue_null_message_fd_r(uint32_t msgid)
{
	return (-1);
}

static int
queue_null_message_corrupt(uint32_t msgid)
{
	return (0);
}

static int
queue_null_envelope_create(uint32_t msgid, const char *buf, size_t len,
    uint64_t *evpid)
{
	*evpid = queue_generate_evpid(msgid);
	return (1);
}

static int
queue_null_envelope_delete(uint64_t evpid)
{
	return (1);
}

static int
queue_null_envelope_update(uint64_t evpid, const char *buf, size_t len)
{
	return (1);
}

static int
queue_null_envelope_load(uint64_t evpid, char *buf, size_t len)
{
	return (0);
}

static int
queue_null_envelope_walk(uint64_t *evpid, char *buf, size_t len)
{
	return (-1);
}

static int
queue_null_init(int server)
{
	queue_api_on_message_create(queue_null_message_create);
	queue_api_on_message_commit(queue_null_message_commit);
	queue_api_on_message_delete(queue_null_message_delete);
	queue_api_on_message_fd_r(queue_null_message_fd_r);
	queue_api_on_message_corrupt(queue_null_message_corrupt);
	queue_api_on_envelope_create(queue_null_envelope_create);
	queue_api_on_envelope_delete(queue_null_envelope_delete);
	queue_api_on_envelope_update(queue_null_envelope_update);
	queue_api_on_envelope_load(queue_null_envelope_load);
	queue_api_on_envelope_walk(queue_null_envelope_walk);

	return (1);
}

int
main(int argc, char **argv)
{
	int	ch;

	log_init(1);

	while ((ch = getopt(argc, argv, "")) != -1) {
		switch (ch) {
		default:
			log_warnx("warn: queue-null: bad option");
			return (1);
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;

	queue_null_init(1);
	queue_api_dispatch();

	return (0);
}
