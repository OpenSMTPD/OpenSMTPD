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

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/param.h>
#include <sys/socket.h>

#include <err.h>
#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "smtpd.h"
#include "log.h"

static void mfa_imsg(struct imsgev *, struct imsg *);
static void mfa_shutdown(void);
static void mfa_sig_handler(int, short, void *);
static void mfa_test_connect(struct mfa_req_msg *);
static void mfa_test_helo(struct mfa_req_msg *);
static void mfa_test_mail(struct mfa_req_msg *);
static void mfa_test_rcpt(struct mfa_req_msg *);
static void mfa_test_dataline(struct mfa_req_msg *);
static void mfa_test_quit(struct mfa_req_msg *);
static void mfa_test_close(struct mfa_req_msg *);
static void mfa_test_rset(struct mfa_req_msg *);
static int mfa_strip_source_route(char *, size_t);
static int mfa_fork_filter(struct filter *);

static void
mfa_imsg(struct imsgev *iev, struct imsg *imsg)
{
	struct mfa_resp_msg	resp;
	struct lka_resp_msg    *lka_resp;
	struct filter	       *filter;

	if (iev->proc == PROC_SMTP) {
		switch (imsg->hdr.type) {
		case IMSG_MFA_CONNECT:
			mfa_test_connect(imsg->data);
			return;
		case IMSG_MFA_HELO:
			mfa_test_helo(imsg->data);
			return;
		case IMSG_MFA_MAIL:
			mfa_test_mail(imsg->data);
			return;
		case IMSG_MFA_RCPT:
			mfa_test_rcpt(imsg->data);
			return;
		case IMSG_MFA_DATALINE:
			mfa_test_dataline(imsg->data);
			return;
		case IMSG_MFA_QUIT:
			mfa_test_quit(imsg->data);
			return;
		case IMSG_MFA_CLOSE:
			mfa_test_close(imsg->data);
			return;
		case IMSG_MFA_RSET:
			mfa_test_rset(imsg->data);
			return;
		}
	}

	if (iev->proc == PROC_LKA) {
		switch (imsg->hdr.type) {
		case IMSG_LKA_EXPAND_RCPT:
			lka_resp = imsg->data;
			resp.reqid = lka_resp->reqid;
			if (lka_resp->status == LKA_OK)
				resp.status = MFA_OK;
			else if (lka_resp->status == LKA_TEMPFAIL)
				resp.status = MFA_TEMPFAIL;
			else if (lka_resp->status == LKA_PERMFAIL)
				resp.status = MFA_PERMFAIL;
			imsg_compose_event(env->sc_ievs[PROC_SMTP],
			    IMSG_MFA_RCPT, 0, 0, -1, &resp, sizeof (resp));
			return;
		}
	}

	if (iev->proc == PROC_PARENT) {
		switch (imsg->hdr.type) {
		case IMSG_CONF_START:
			env->sc_filters = xcalloc(1, sizeof *env->sc_filters,
			    "mfa_imsg");
			TAILQ_INIT(env->sc_filters);
			return;

		case IMSG_CONF_FILTER:
			filter = xmemdup(imsg->data, sizeof *filter,
			    "mfa_imsg");
			TAILQ_INSERT_TAIL(env->sc_filters, filter, f_entry);
			return;

		case IMSG_CONF_END:
			TAILQ_FOREACH(filter, env->sc_filters, f_entry) {
				log_info("info: Forking filter: %s",
				    filter->name);
				if (! mfa_fork_filter(filter))
					fatalx("could not fork filter");
			}
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
	struct filter *filter;

	TAILQ_FOREACH(filter, env->sc_filters, f_entry) {
		kill(filter->pid, SIGTERM);
	}

	do {
		pid = waitpid(WAIT_MYPGRP, NULL, 0);
	} while (pid != -1 || (pid == -1 && errno == EINTR));

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

	struct peer peers[] = {
		{ PROC_PARENT,	imsg_dispatch },
		{ PROC_SMTP,	imsg_dispatch },
		{ PROC_LKA,	imsg_dispatch },
		{ PROC_CONTROL,	imsg_dispatch }
	};

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
			fatalx("unknown user " SMTPD_FILTER_USER);
	pw = env->sc_pw;

	smtpd_process = PROC_MFA;
	setproctitle("%s", env->sc_title[smtpd_process]);

	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("mfa: cannot drop privileges");

	imsg_callback = mfa_imsg;
	event_init();

	SPLAY_INIT(&env->mfa_sessions);
	TAILQ_INIT(env->sc_filters);

	signal_set(&ev_sigint, SIGINT, mfa_sig_handler, NULL);
	signal_set(&ev_sigterm, SIGTERM, mfa_sig_handler, NULL);
	signal_set(&ev_sigchld, SIGCHLD, mfa_sig_handler, NULL);
	signal_add(&ev_sigint, NULL);
	signal_add(&ev_sigterm, NULL);
	signal_add(&ev_sigchld, NULL);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	config_pipes(peers, nitems(peers));
	config_peers(peers, nitems(peers));

	if (event_dispatch() < 0)
		fatal("event_dispatch");
	mfa_shutdown();

	return (0);
}

static void
mfa_test_connect(struct mfa_req_msg *d)
{
	union mfa_session_data	data;

	data.evp = d->evp;
	mfa_session(d->reqid, S_CONNECTED, &data);
}

static void
mfa_test_helo(struct mfa_req_msg *d)
{
	union mfa_session_data	data;

	data.evp = d->evp;
	mfa_session(d->reqid, S_HELO, &data);
}

static void
mfa_test_mail(struct mfa_req_msg *d)
{
	struct envelope	       *e = &d->evp;
	struct mfa_resp_msg	mfa_resp;
	union mfa_session_data	data;

	if (mfa_strip_source_route(e->sender.user, sizeof(e->sender.user)))
		goto refuse;

	if (! valid_localpart(e->sender.user) ||
	    ! valid_domainpart(e->sender.user)) {
		/*
		 * "MAIL FROM:<>" is the exception we allow.
		 */
		if (!(e->sender.user[0] == '\0' &&
			e->sender.domain[0] == '\0'))
			goto refuse;
	}

	data.evp = d->evp;
	mfa_session(d->reqid, S_MAIL_MFA, &data);
	return;

refuse:
	mfa_resp.reqid = d->reqid;
	mfa_resp.status = MFA_PERMFAIL;
	imsg_compose_event(env->sc_ievs[PROC_SMTP], IMSG_MFA_MAIL, 0, 0, -1,
	    &mfa_resp, sizeof(mfa_resp));
	return;
}

static void
mfa_test_rcpt(struct mfa_req_msg *d)
{
	struct envelope	       *e = &d->evp;
	struct mfa_resp_msg	mfa_resp;
	union mfa_session_data	data;

	mfa_strip_source_route(e->rcpt.user, sizeof(e->rcpt.user));

	if (! valid_localpart(e->rcpt.user) ||
	    ! valid_domainpart(e->rcpt.domain))
		goto refuse;

	data.evp = d->evp;
	mfa_session(d->reqid, S_RCPT_MFA, &data);
	return;

refuse:
	mfa_resp.reqid = d->reqid;
	mfa_resp.status = MFA_PERMFAIL;
	imsg_compose_event(env->sc_ievs[PROC_SMTP], IMSG_MFA_RCPT, 0, 0, -1,
	    &mfa_resp, sizeof(mfa_resp));
}

static void
mfa_test_dataline(struct mfa_req_msg *d)
{
	union mfa_session_data	data;

	strlcpy(data.buffer, d->buffer, sizeof data.buffer);
	mfa_session(d->reqid, S_DATACONTENT, &data);
}

static void
mfa_test_quit(struct mfa_req_msg *d)
{
	union mfa_session_data	data;

	data.evp = d->evp;
	mfa_session(d->reqid, S_QUIT, &data);
}

static void
mfa_test_close(struct mfa_req_msg *d)
{
	union mfa_session_data	data;

	data.evp = d->evp;
	mfa_session(d->reqid, S_CLOSE, &data);
}

static void
mfa_test_rset(struct mfa_req_msg *d)
{
	union mfa_session_data	data;

	data.evp = d->evp;
	mfa_session(d->reqid, S_RSET, &data);
}

static int
mfa_strip_source_route(char *buf, size_t len)
{
	char *p;

	p = strchr(buf, ':');
	if (p != NULL) {
		p++;
		memmove(buf, p, strlen(p) + 1);
		return 1;
	}

	return 0;
}

static int
mfa_fork_filter(struct filter *filter)
{
	pid_t	pid;
	int	sockpair[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, sockpair) < 0)
		return 0;

	session_socket_blockmode(sockpair[0], BM_NONBLOCK);
	session_socket_blockmode(sockpair[1], BM_NONBLOCK);

	filter->ibuf = calloc(1, sizeof(struct imsgbuf));
	if (filter->ibuf == NULL)
		goto err;

	pid = fork();
	if (pid == -1)
		goto err;

	if (pid == 0) {
		/* filter */
		dup2(sockpair[0], STDIN_FILENO);

		if (closefrom(STDERR_FILENO + 1) < 0)
			exit(1);

		execl(filter->path, filter->name, NULL);
		exit(1);
	}

	/* in parent */
	close(sockpair[0]);
	imsg_init(filter->ibuf, sockpair[1]);

	return 1;

err:
	free(filter->ibuf);
	close(sockpair[0]);
	close(sockpair[1]);
	return 0;
}
