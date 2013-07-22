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

#include <stdlib.h>
#include <unistd.h>

#include "smtpd-defines.h"
#include "smtpd-api.h"
#include "log.h"

static int
scheduler_stub_init(void)
{
	return (1);
}

static int
scheduler_stub_insert(struct scheduler_info *info)
{
	return (0);
}

static size_t
scheduler_stub_commit(uint32_t msgid)
{
	return (0);
}

static size_t
scheduler_stub_rollback(uint32_t msgid)
{
	return (0);
}

static int
scheduler_stub_update(struct scheduler_info *info)
{
	return (0);
}

static int
scheduler_stub_delete(uint64_t evpid)
{
	return (0);
}

static int
scheduler_stub_batch(int mask, struct scheduler_batch *batch)
{
	batch->type = SCHED_NONE;
	batch->evpcount = 0;
	return (0);
}

static size_t
scheduler_stub_messages(uint32_t msgid, uint32_t *dst, size_t sz)
{
	return (0);
}

static size_t
scheduler_stub_envelopes(uint64_t evpid, struct evpstate *dst, size_t sz)
{
	return (0);
}

static int
scheduler_stub_schedule(uint64_t evpid)
{
	return (0);
}

static int
scheduler_stub_remove(uint64_t evpid)
{
	return (0);
}

static int
scheduler_stub_suspend(uint64_t evpid)
{
	return (0);
}

static int
scheduler_stub_resume(uint64_t evpid)
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
			log_warnx("warn: backend-scheduler-stub: bad option");
			exit(1);
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;

	scheduler_api_on_init(scheduler_stub_init);
	scheduler_api_on_insert(scheduler_stub_insert);
	scheduler_api_on_commit(scheduler_stub_commit);
	scheduler_api_on_rollback(scheduler_stub_rollback);
	scheduler_api_on_update(scheduler_stub_update);
	scheduler_api_on_delete(scheduler_stub_delete);
	scheduler_api_on_batch(scheduler_stub_batch);
	scheduler_api_on_messages(scheduler_stub_messages);
	scheduler_api_on_envelopes(scheduler_stub_envelopes);
	scheduler_api_on_schedule(scheduler_stub_schedule);
	scheduler_api_on_remove(scheduler_stub_remove);
	scheduler_api_on_suspend(scheduler_stub_suspend);
	scheduler_api_on_resume(scheduler_stub_resume);

	scheduler_api_dispatch();

	return (0);
}
