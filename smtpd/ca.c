/*	$OpenBSD$	*/

/*
 * Copyright (c) 2012 Gilles Chehade <gilles@openbsd.org>
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
#include <sys/uio.h>

#include <err.h>
#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <netdb.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "smtpd.h"
#include "log.h"

static void ca_imsg(struct mproc *, struct imsg *);
static void ca_shutdown(void);
static void ca_sig_handler(int, short, void *);

static void
ca_imsg(struct mproc *p, struct imsg *imsg)
{
	struct ca_cert_req_msg *req_ca_cert;
	struct ca_cert_resp_msg	resp_ca_cert;
	struct ssl	       *ssl;
	struct iovec		iov[3];

	if (p->proc == PROC_SMTP) {
		switch (imsg->hdr.type) {
		}
	}

	if (p->proc == PROC_PARENT) {
		switch (imsg->hdr.type) {

		case IMSG_CONF_START:
			if (env->sc_flags & SMTPD_CONFIGURING)
				return;
			env->sc_flags |= SMTPD_CONFIGURING;
			env->sc_ssl_dict = calloc(1, sizeof *env->sc_ssl_dict);
			if (env->sc_ssl_dict == NULL)
				fatal(NULL);
			return;

		case IMSG_CONF_END:
			if (!(env->sc_flags & SMTPD_CONFIGURING))
				return;
			env->sc_flags &= ~SMTPD_CONFIGURING;
			return;

		case IMSG_CTL_VERBOSE:
			log_verbose(*(int *)imsg->data);
			return;
		}
	}

	errx(1, "ca_imsg: unexpected %s imsg", imsg_to_str(imsg->hdr.type));
}

static void
ca_sig_handler(int sig, short event, void *p)
{
	switch (sig) {
	case SIGINT:
	case SIGTERM:
		ca_shutdown();
		break;
	default:
		fatalx("ca_sig_handler: unexpected signal");
	}
}

static void
ca_shutdown(void)
{
	log_info("info: ca process exiting");
	_exit(0);
}

pid_t
ca(void)
{
	pid_t		 pid;
	struct passwd	*pw;
	struct event	 ev_sigint;
	struct event	 ev_sigterm;

	switch (pid = fork()) {
	case -1:
		fatal("ca: cannot fork");
	case 0:
		break;
	default:
		return (pid);
	}

	purge_config(PURGE_EVERYTHING);

	pw = env->sc_pw;

	/*
	  if (chroot(PATH_CERTIFICATES) == -1)
	  fatal("ca: chroot");
	  if (chdir("/") == -1)
	  fatal("ca: chdir(\"/\")");
	*/

	smtpd_process = PROC_CA;
	setproctitle("%s", env->sc_title[smtpd_process]);

	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("smtp: cannot drop privileges");

	imsg_callback = ca_imsg;
	event_init();

	signal_set(&ev_sigint, SIGINT, ca_sig_handler, NULL);
	signal_set(&ev_sigterm, SIGTERM, ca_sig_handler, NULL);
	signal_add(&ev_sigint, NULL);
	signal_add(&ev_sigterm, NULL);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	config_peer(PROC_PARENT);
	config_peer(PROC_SMTP);
	config_peer(PROC_MTA);

	config_done();

	if (event_dispatch() < 0)
		fatal("event_dispatch");
	ca_shutdown();

	return (0);
}
