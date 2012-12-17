/*	$OpenBSD: mfa_session.c,v 1.11 2012/10/11 21:51:37 gilles Exp $	*/

/*
 * Copyright (c) 2011 Gilles Chehade <gilles@openbsd.org>
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

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <netinet/in.h>

#include <ctype.h>
#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <resolv.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "smtpd.h"
#include "log.h"


struct mfa_filter {
	TAILQ_ENTRY(mfa_filter)		 entry;
	struct mproc			 mproc;
};

struct mfa_filter_chain {
	TAILQ_HEAD(, mfa_filter)	filters;
};

struct mfa_request {
	uint64_t		 conn_id;
	uint64_t		 req_id;
	struct mfa_filter	*current; /* the filter currently running */
	struct tree		 notify;  /* list of filters to notify */
};

static struct mfa_filter_chain	chain;

static void
mfa_session_init(void)
{
	static int		 init = 0;
	struct filter		*filter;
	void			*iter;
	struct mfa_filter	*f;
	struct mproc		*p;
	int			 r;
	uint32_t		 v = FILTER_API_VERSION;

	if (init)
		return;
	init = 1;

	TAILQ_INIT(&chain.filters);

	iter = NULL;
	while (dict_iter(&env->sc_filters, &iter, NULL, (void **)&filter)) {
		f = xcalloc(1, sizeof *f, "mfa_session_init");
		p = &f->mproc;
		r = mproc_fork(p, filter->path, filter->name);
		m_compose(p, HOOK_REGISTER, 0, 0, -1, &v, sizeof(v));
		mproc_enable(p);
		TAILQ_INSERT_TAIL(&chain.filters, f, entry);
	}
}

static void
mfa_finalize(struct mfa_request *req)
{
	struct mfa_filter	*f;

	while (tree_poproot(&req->notify, NULL, (void**)&f)) {
		/*
		mfa_filter_notify(f,);
		*/
	}
	/*
	imsg_compose_event(env->sc_ievs[PROC_SMTP], ???);
	*/
};
