/*	$OpenBSD: mfa_session.c,v 1.11 2012/10/11 21:51:37 gilles Exp $	*/

/*
 * Copyright (c) 2011 Gilles Chehade <gilles@openbsd.org>
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

static void mfa_session_destroy(struct mfa_session *);
static void mfa_session_done(struct mfa_session *);
void mfa_session_imsg_handler(struct imsg *, void *);

void
mfa_session_filters_init(void)
{
	struct filter  *filter;
	void	       *iter;

	iter = NULL;
	while (dict_iter(&env->sc_filters, &iter, NULL, (void **)&filter)) {
		filter->process = imsgproc_fork(filter->path, filter->name,
		    mfa_session_imsg_handler, NULL);
		if (filter->process == NULL)
			fatalx("could not start filter");
		imsgproc_set_read(filter->process);
	}
}

void
mfa_session(struct submit_status *ss, enum session_state state)
{
	struct mfa_session *ms;

	ms = xcalloc(1, sizeof(*ms), "mfa_session");
	ms->id    = ss->id;
	ms->ss    = *ss;
	ms->state = state;
 	ms->ss.code = 250;

	tree_xset(&env->mfa_sessions, ms->id, ms);

	mfa_session_done(ms);

	/*
	tree_xset(&sessions, ms->id, ms);
	if (! dict_iter(&env->sc_filters, &ms->iter, NULL, (void **)&ms->filter))
		mfa_session_done(ms);
	else if (!mfa_session_proceed(ms))
		mfa_session_fail(ms);
	*/
}

static void
mfa_session_done(struct mfa_session *ms)
{
	enum imsg_type	imsg_type;

	switch (ms->state) {
	case S_CONNECTED:
		imsg_type = IMSG_MFA_CONNECT;
		break;
	case S_HELO:
		imsg_type = IMSG_MFA_HELO;
		break;
	case S_MAIL_MFA:
		if ((ms->ss.code / 100) == 2) {
			imsg_compose_event(env->sc_ievs[PROC_LKA],
                            IMSG_LKA_MAIL, 0, 0, -1,
                            &ms->ss, sizeof(ms->ss));
                        mfa_session_destroy(ms);
                        return;
		}
		imsg_type = IMSG_MFA_MAIL;
		break;
	case S_RCPT_MFA:
		if ((ms->ss.code / 100) == 2) {
			imsg_compose_event(env->sc_ievs[PROC_LKA],
                            IMSG_LKA_RULEMATCH, 0, 0, -1,
                            &ms->ss, sizeof(ms->ss));
                        mfa_session_destroy(ms);
                        return;
		}
		imsg_type = IMSG_MFA_RCPT;
		break;
	case S_DATACONTENT:
		imsg_type = IMSG_MFA_DATALINE;
		break;
	case S_QUIT:
		imsg_type = IMSG_MFA_QUIT;
		break;
	case S_CLOSE:
		mfa_session_destroy(ms);
		return;
	case S_RSET:
		imsg_type = IMSG_MFA_RSET;
		break;
	default:
		fatalx("mda_session_done: unsupported state");
	}
	imsg_compose_event(env->sc_ievs[PROC_SMTP], imsg_type, 0, 0,
            -1, &ms->ss, sizeof(struct submit_status));
        mfa_session_destroy(ms);
}

static void
mfa_session_fail(struct mfa_session *ms)
{
}

static void
mfa_session_destroy(struct mfa_session *ms)
{
	tree_xpop(&env->mfa_sessions, ms->id);
	free(ms);
}

void
mfa_session_imsg_handler(struct imsg *imsg, void *arg)
{
	switch (imsg->hdr.type) {
	case FILTER_REGISTER:
		log_debug("REGISTERING HOOK %d", *(uint32_t *)imsg->data);
		break;
	default:
		log_debug("NOT HANDLED YET !\n", imsg->hdr.type);
		break;
	}
}
