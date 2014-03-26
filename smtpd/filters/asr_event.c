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

#include <stdlib.h>

#include "asr.h"
#include "asr_event.h"

void async_event_dispatch(int, short, void *);

struct async_event *
async_run_event(struct asr_query * async,
    void (*cb)(struct asr_result *, void *), void *arg)
{
	struct async_event	*aev;
	struct timeval		 tv;

	aev = calloc(1, sizeof *aev);
	aev->async = async;
	aev->callback = cb;
	aev->arg = arg;
	tv.tv_sec = 0;
	tv.tv_usec = 1;
	evtimer_set(&aev->ev, async_event_dispatch, aev);
	evtimer_add(&aev->ev, &tv);
	return (aev);
}

void
async_event_dispatch(int fd, short ev, void *arg)
{
	struct async_event	*aev = arg;
	struct asr_result	 ar;
	struct timeval		 tv;

	event_del(&aev->ev);
	if (asr_run(aev->async, &ar) == 0) {
		event_set(&aev->ev, ar.ar_fd,
		    ar.ar_cond == ASR_WANT_READ ? EV_READ : EV_WRITE,
		    async_event_dispatch, aev);
		tv.tv_sec = ar.ar_timeout / 1000;
		tv.tv_usec = (ar.ar_timeout % 1000) * 1000;
		event_add(&aev->ev, &tv);
	} else { /* done */
		aev->callback(&ar, aev->arg);
		free(aev);
	}
}
