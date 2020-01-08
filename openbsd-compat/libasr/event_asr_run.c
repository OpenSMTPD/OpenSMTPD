/*	$OpenBSD$	*/
/*
 * Copyright (c) 2012 Eric Faurot <eric@openbsd.org>
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
#include <sys/socket.h>
#include <netdb.h>

#include <asr.h>
#include <event.h>
#include <stdlib.h>

struct event_asr {
	struct event	 ev;
	struct asr_query *async;
	void		(*cb)(struct asr_result *, void *);
	void		*arg;
};

struct event_asr * event_asr_run(struct asr_query *,
    void (*)(struct asr_result *, void *), void *);
void event_asr_abort(struct event_asr *);

static void
event_asr_dispatch(int fd __attribute__((__unused__)),
    short ev __attribute__((__unused__)), void *arg)
{
	struct event_asr	*eva = arg;
	struct asr_result	 ar;
	struct timeval		 tv;

	event_del(&eva->ev);

	if (asr_run(eva->async, &ar)) {
		eva->cb(&ar, eva->arg);
		free(eva);
	} else {
		event_set(&eva->ev, ar.ar_fd,
		    ar.ar_cond == ASR_WANT_READ ? EV_READ : EV_WRITE,
		    event_asr_dispatch, eva);
		tv.tv_sec = ar.ar_timeout / 1000;
		tv.tv_usec = (ar.ar_timeout % 1000) * 1000;
		event_add(&eva->ev, &tv);
	}
}

struct event_asr *
event_asr_run(struct asr_query *async, void (*cb)(struct asr_result *, void *),
    void *arg)
{
	struct event_asr *eva;
	struct timeval tv;

	eva = calloc(1, sizeof *eva);
	if (eva == NULL)
		return (NULL);
	eva->async = async;
	eva->cb = cb;
	eva->arg = arg;
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	evtimer_set(&eva->ev, event_asr_dispatch, eva);
	evtimer_add(&eva->ev, &tv);
	return (eva);
}

void
event_asr_abort(struct event_asr *eva)
{
	asr_abort(eva->async);
	event_del(&eva->ev);
	free(eva);
}
