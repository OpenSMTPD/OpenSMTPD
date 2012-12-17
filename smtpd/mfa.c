/*	$OpenBSD: mfa.c,v 1.73 2012/11/12 14:58:53 eric Exp $	*/

/*
 * Copyright (c) 2008 Gilles Chehade <gilles@openbsd.org>
 * Copyright (c) 2008 Pierre-Yves Ritschard <pyr@openbsd.org>
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
#include <sys/wait.h>
#include "sys-queue.h"
#include "sys-tree.h"
#include <sys/param.h>
#include <sys/socket.h>

#include <err.h>
#include <errno.h>
#include <event.h>
#include <grp.h> /* needed for setgroups */
#include "imsg.h"
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "smtpd.h"
#include "log.h"

static void mfa_imsg(struct mproc *, struct imsg *);
static void mfa_shutdown(void);
static void mfa_sig_handler(int, short, void *);

static void
mfa_imsg(struct mproc *p, struct imsg *imsg)
{
	struct mfa_connect_msg		*req_connect;
	struct mfa_req_msg		*req;
	struct mfa_smtp_resp_msg	 resp;
	struct filter			*filter;

	if (p->proc == PROC_SMTP) {
		switch (imsg->hdr.type) {
		case IMSG_MFA_REQ_CONNECT:
			req_connect = imsg->data;

			log_debug("mfa: CONNECT %s <-> %s",
			    ss_to_text(&req_connect->local),
			    ss_to_text(&req_connect->peer));

			resp.reqid = req_connect->reqid;
			resp.status = MFA_OK;
			resp.code = 0;
			resp.line[0] = '\0';
			m_compose(p, IMSG_MFA_SMTP_RESPONSE, 0, 0, -1,
			    &resp, sizeof(resp));
			return;

		case IMSG_MFA_REQ_HELO:
		case IMSG_MFA_REQ_MAIL:
		case IMSG_MFA_REQ_RCPT:
		case IMSG_MFA_REQ_DATA:
		case IMSG_MFA_REQ_EOM:
			req = imsg->data;
			resp.reqid = req->reqid;
			resp.status = MFA_OK;
			resp.code = 0;
			resp.line[0] = '\0';
			m_compose(p, IMSG_MFA_SMTP_RESPONSE, 0, 0, -1,
			    &resp, sizeof(resp));
			return;

		case IMSG_MFA_SMTP_DATA:
			m_forward(p, imsg);
			return;

		case IMSG_MFA_EVENT_RSET:
		case IMSG_MFA_EVENT_COMMIT:
		case IMSG_MFA_EVENT_DISCONNECT:
			/* No reponse expected */
			return;
		}
	}

	if (p->proc == PROC_PARENT) {
		switch (imsg->hdr.type) {
		case IMSG_CONF_START:
			dict_init(&env->sc_filters);
			return;

		case IMSG_CONF_FILTER:
			filter = xmemdup(imsg->data, sizeof *filter,
			    "mfa_imsg");
			dict_set(&env->sc_filters, filter->name, filter);
			return;

		case IMSG_CONF_END:
			return;

		case IMSG_CTL_VERBOSE:
			log_verbose(*(int *)imsg->data);
			return;
		}
	}

	errx(1, "mfa_imsg: unexpected %s imsg", imsg_to_str(imsg->hdr.type));
}

static void
mfa_sig_handler(int sig, short event, void *p)
{
	switch (sig) {
	case SIGINT:
	case SIGTERM:
		mfa_shutdown();
		break;

	case SIGCHLD:
		fatalx("unexpected SIGCHLD");
		break;

	default:
		fatalx("mfa_sig_handler: unexpected signal");
	}
}

static void
mfa_shutdown(void)
{
	pid_t pid;

	do {
		pid = waitpid(WAIT_MYPGRP, NULL, 0);
	} while (pid != -1 || (pid == -1 && errno == EINTR));

#ifdef VALGRIND
	child_free();
	free_peers();
	clean_setproctitle();
	event_base_free(NULL);
#endif

	log_info("info: mail filter exiting");
	_exit(0);
}


pid_t
mfa(void)
{
	pid_t		 pid;
	struct passwd	*pw;
	struct event	 ev_sigint;
	struct event	 ev_sigterm;
	struct event	 ev_sigchld;

	switch (pid = fork()) {
	case -1:
		fatal("mfa: cannot fork");
	case 0:
		break;
	default:
		return (pid);
	}

	purge_config(PURGE_EVERYTHING);

	if ((env->sc_pw =  getpwnam(SMTPD_FILTER_USER)) == NULL)
		if ((env->sc_pw =  getpwnam(SMTPD_USER)) == NULL)
			fatalx("unknown user " SMTPD_USER);
	pw = env->sc_pw;

	smtpd_process = PROC_MFA;
	setproctitle("%s", env->sc_title[smtpd_process]);

	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("mfa: cannot drop privileges");

	imsg_callback = mfa_imsg;
	event_init();

	signal_set(&ev_sigint, SIGINT, mfa_sig_handler, NULL);
	signal_set(&ev_sigterm, SIGTERM, mfa_sig_handler, NULL);
	signal_set(&ev_sigchld, SIGCHLD, mfa_sig_handler, NULL);
	signal_add(&ev_sigint, NULL);
	signal_add(&ev_sigterm, NULL);
	signal_add(&ev_sigchld, NULL);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	config_peer(PROC_PARENT);
	config_peer(PROC_SMTP);
	config_peer(PROC_CONTROL);
	config_done();

	imsgproc_init();
	if (event_dispatch() < 0)
		fatal("event_dispatch");
	mfa_shutdown();

	return (0);
}
