/*
 * Copyright (c) 2026 Guy Godfroy <guy.godfroy@ovhcloud.com>
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
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/socket.h>

#include <event.h>
#include <imsg.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "smtpd.h"

/*
 * Producer side of the "queue" report subsystem.  Runs in the queue process,
 * which peers with lka, and mirrors report_smtp.c.
 *
 * The queue is the only place that sees the outcome of every delivery, local
 * and remote alike, with the whole envelope in scope.  The scheduler decides
 * expiry but cannot report it: it has no lka peer.
 */

static const char *
report_queue_type(const struct envelope *evp)
{
	switch (evp->type) {
	case D_MDA:
		return "mda";
	case D_MTA:
		return "mta";
	case D_BOUNCE:
		return "bounce";
	}
	return "unknown";
}

/*
 * Everything an envelope contributes to a metric, minus the free-text error.
 * The delay is what the delivery log prints as "delay=".
 */
static void
report_queue_envelope(struct mproc *p, const struct envelope *evp)
{
	const char	*domain;

	m_add_id(p, evp->id);
	m_add_string(p, report_queue_type(evp));
	m_add_string(p, evp->dispatcher);
	m_add_u32(p, (uint32_t)evp->retry);
	m_add_time(p, time(NULL) - evp->creation);

	domain = evp->dest.domain;
	m_add_string(p, domain ? domain : "");
}

void
report_queue_delivery(const struct envelope *evp, const char *result)
{
	struct timeval	tv;

	gettimeofday(&tv, NULL);

	m_create(p_lka, IMSG_REPORT_QUEUE_DELIVERY, 0, 0, -1);
	m_add_timeval(p_lka, &tv);
	report_queue_envelope(p_lka, evp);
	m_add_string(p_lka, result);
	m_add_string(p_lka, evp->esc_class ?
	    esc_code(evp->esc_class, evp->esc_code) : "");
	m_close(p_lka);
}

void
report_queue_expire(const struct envelope *evp)
{
	struct timeval	tv;

	gettimeofday(&tv, NULL);

	m_create(p_lka, IMSG_REPORT_QUEUE_EXPIRE, 0, 0, -1);
	m_add_timeval(p_lka, &tv);
	report_queue_envelope(p_lka, evp);
	m_close(p_lka);
}

void
report_queue_remove(const struct envelope *evp)
{
	struct timeval	tv;

	gettimeofday(&tv, NULL);

	m_create(p_lka, IMSG_REPORT_QUEUE_REMOVE, 0, 0, -1);
	m_add_timeval(p_lka, &tv);
	report_queue_envelope(p_lka, evp);
	m_close(p_lka);
}
