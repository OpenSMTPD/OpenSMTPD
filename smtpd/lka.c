/*	$OpenBSD: lka.c,v 1.146 2012/11/12 14:58:53 eric Exp $	*/

/*
 * Copyright (c) 2008 Pierre-Yves Ritschard <pyr@openbsd.org>
 * Copyright (c) 2008 Gilles Chehade <gilles@openbsd.org>
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
#include <err.h>
#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <pwd.h>
#include <resolv.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "smtpd.h"
#include "log.h"

static void lka_imsg(struct imsgev *, struct imsg *);
static void lka_shutdown(void);
static void lka_sig_handler(int, short, void *);
static int lka_verify_mail(struct mailaddr *);
static int lka_encode_credentials(char *, size_t, struct table_credentials *);


static void
lka_imsg(struct imsgev *iev, struct imsg *imsg)
{
	struct submit_status	*ss;
	struct secret		*secret;
	struct rule		*rule;
	struct table		*table;
	void			*tmp;
	int			ret;
	const char		*k;
	const char		*v;
	static struct dict		*tables_dict;
	static struct tree		*tables_tree;
	static struct table		*table_last;

	if (imsg->hdr.type == IMSG_DNS_HOST || imsg->hdr.type == IMSG_DNS_MX ||
	    imsg->hdr.type == IMSG_DNS_PTR) {
		dns_async(iev, imsg->hdr.type, imsg->data);
		return;
	}

	if (iev->proc == PROC_MFA) {
		switch (imsg->hdr.type) {
		case IMSG_LKA_MAIL:
			ss = imsg->data;
			ss->code = 530;
			if (ss->u.maddr.user[0] == '\0' &&
			    ss->u.maddr.domain[0] == '\0')
				ss->code = 250;
			else
				if (lka_verify_mail(&ss->u.maddr))
					ss->code = 250;
			imsg_compose_event(iev, IMSG_LKA_MAIL, 0, 0, -1, ss,
			    sizeof *ss);
			return;

		case IMSG_LKA_RULEMATCH:
			ss = imsg->data;
			rule = ruleset_match(&ss->envelope);
			if (rule == NULL)
				ss->code = (errno == EAGAIN) ? 451 : 530;
			else
				ss->code = (rule->r_decision == R_ACCEPT) ?
				    250 : 530;
			imsg_compose_event(iev, IMSG_LKA_RULEMATCH, 0, 0, -1,
			    ss, sizeof *ss);
			return;

		case IMSG_LKA_RCPT:
			lka_session(imsg->data);
			return;
		}
	}

	if (iev->proc == PROC_MTA) {
		switch (imsg->hdr.type) {
		case IMSG_LKA_SECRET: {
			struct table_credentials *table_credentials = NULL;

			secret = imsg->data;
			table = table_findbyname(secret->tablename);
			if (table == NULL) {
				log_warn("warn: Credentials table %s missing",
				    secret->tablename);
				imsg_compose_event(iev, IMSG_LKA_SECRET, 0, 0,
				    -1, secret, sizeof *secret);
				return;
			}
			ret = table_lookup(table, secret->host, K_CREDENTIALS,
			    (void **)&table_credentials);

			log_debug("debug: lka: %s credentials lookup (%d)",
			    secret->host, ret);

			secret->secret[0] = '\0';
			if (ret == -1)
				log_warnx("warn: Credentials lookup fail for "
				    "%s", secret->host);
			else if (ret == 0)
				log_debug("debug: %s credentials not found",
				    secret->host);
			else if (lka_encode_credentials(secret->secret,
				sizeof secret->secret, table_credentials) == 0)
				log_warnx("warn: Credentials parse error for "
				    "%s", secret->host);
			imsg_compose_event(iev, IMSG_LKA_SECRET, 0, 0, -1,
			    secret, sizeof *secret);
			free(table_credentials);
			return;
		}
		}
	}

	if (iev->proc == PROC_PARENT) {
		switch (imsg->hdr.type) {
		case IMSG_CONF_START:
			env->sc_rules_reload = xcalloc(1,
			    sizeof *env->sc_rules, "lka:sc_rules_reload");
			tables_dict = xcalloc(1,
			    sizeof *tables_dict, "lka:tables_dict");
			tables_tree = xcalloc(1,
			    sizeof *tables_tree, "lka:tables_tree");

			dict_init(tables_dict);
			tree_init(tables_tree);
			TAILQ_INIT(env->sc_rules_reload);

			return;

		case IMSG_CONF_RULE:
			rule = xmemdup(imsg->data, sizeof *rule, "lka:rule");
			TAILQ_INSERT_TAIL(env->sc_rules_reload, rule, r_entry);
			return;

		case IMSG_CONF_TABLE:
			table_last = table = xmemdup(imsg->data, sizeof *table,
			    "lka:table");
			dict_init(&table->t_dict);
			dict_set(tables_dict, table->t_name, table);
			tree_set(tables_tree, table->t_id, table);
			return;

		case IMSG_CONF_RULE_SOURCE:
			rule = TAILQ_LAST(env->sc_rules_reload, rulelist);
			tmp = env->sc_tables_dict;
			env->sc_tables_dict = tables_dict;
			rule->r_sources = table_findbyname(imsg->data);
			if (rule->r_sources == NULL)
				fatalx("lka: tables inconsistency");
			env->sc_tables_dict = tmp;
			return;

		case IMSG_CONF_TABLE_CONTENT:
			table = table_last;

			k = imsg->data;
			if (table->t_type == T_HASH)
				v = k + strlen(k) + 1;
			else
				v = NULL;

			dict_set(&table->t_dict, k,
			    v ? xstrdup(v, "lka:dict_set") : NULL);
			return;

		case IMSG_CONF_END:

			if (env->sc_rules)
				purge_config(PURGE_RULES);
			if (env->sc_tables_tree) {
				table_close_all();
				purge_config(PURGE_TABLES);
			}
			env->sc_rules = env->sc_rules_reload;
			env->sc_tables_dict = tables_dict;
			env->sc_tables_tree = tables_tree;
			table_open_all();

			table_last = NULL;
			tables_dict = NULL;
			tables_tree = NULL;

			/* start fulfilling requests */
			event_add(&env->sc_ievs[PROC_MTA]->ev, NULL);
			event_add(&env->sc_ievs[PROC_MFA]->ev, NULL);
			event_add(&env->sc_ievs[PROC_SMTP]->ev, NULL);
			return;

		case IMSG_CTL_VERBOSE:
			log_verbose(*(int *)imsg->data);
			return;

		case IMSG_PARENT_FORWARD_OPEN:
			lka_session_forward_reply(imsg->data, imsg->fd);
			return;

		}
	}

	if (iev->proc == PROC_CONTROL) {
		switch (imsg->hdr.type) {
		case IMSG_LKA_UPDATE_TABLE:
			table = table_findbyname(imsg->data);
			if (table == NULL) {
				log_warnx("warn: Lookup table not found: "
				    "\"%s\"", (char *)imsg->data);
				return;
			}
			table_update(table);
			return;
		}
	}

	errx(1, "lka_imsg: unexpected %s imsg", imsg_to_str(imsg->hdr.type));
}

static void
lka_sig_handler(int sig, short event, void *p)
{
	int status;
	pid_t pid;

	switch (sig) {
	case SIGINT:
	case SIGTERM:
		lka_shutdown();
		break;
	case SIGCHLD:
		do {
			pid = waitpid(-1, &status, WNOHANG);
		} while (pid > 0 || (pid == -1 && errno == EINTR));
		break;
	default:
		fatalx("lka_sig_handler: unexpected signal");
	}
}

void
lka_shutdown(void)
{
	log_info("info: lookup agent exiting");
	_exit(0);
}

pid_t
lka(void)
{
	pid_t		 pid;
	struct passwd	*pw;

	struct event	 ev_sigint;
	struct event	 ev_sigterm;
	struct event	 ev_sigchld;

	struct peer peers[] = {
		{ PROC_PARENT,	imsg_dispatch },
		{ PROC_MFA,	imsg_dispatch },
		{ PROC_QUEUE,	imsg_dispatch },
		{ PROC_SMTP,	imsg_dispatch },
		{ PROC_MTA,	imsg_dispatch },
		{ PROC_CONTROL,	imsg_dispatch }
	};

	switch (pid = fork()) {
	case -1:
		fatal("lka: cannot fork");
	case 0:
		break;
	default:
		return (pid);
	}

	purge_config(PURGE_EVERYTHING);

	pw = env->sc_pw;

	smtpd_process = PROC_LKA;
	setproctitle("%s", env->sc_title[smtpd_process]);

	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("lka: cannot drop privileges");

	imsg_callback = lka_imsg;
	event_init();
	SPLAY_INIT(&env->lka_sessions);

	signal_set(&ev_sigint, SIGINT, lka_sig_handler, NULL);
	signal_set(&ev_sigterm, SIGTERM, lka_sig_handler, NULL);
	signal_set(&ev_sigchld, SIGCHLD, lka_sig_handler, NULL);
	signal_add(&ev_sigint, NULL);
	signal_add(&ev_sigterm, NULL);
	signal_add(&ev_sigchld, NULL);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	/*
	 * lka opens all kinds of files and sockets, so bump the limit to max.
	 * XXX: need to analyse the exact hard limit.
	 */
	fdlimit(1.0);

	config_pipes(peers, nitems(peers));
	config_peers(peers, nitems(peers));

	/* ignore them until we get our config */
	event_del(&env->sc_ievs[PROC_MTA]->ev);
	event_del(&env->sc_ievs[PROC_MFA]->ev);
	event_del(&env->sc_ievs[PROC_SMTP]->ev);

	if (event_dispatch() < 0)
		fatal("event_dispatch");
	lka_shutdown();

	return (0);
}

static int
lka_verify_mail(struct mailaddr *maddr)
{
	return 1;
}

static int
lka_encode_credentials(char *dst, size_t size,
    struct table_credentials *table_credentials)
{
	char	*buf;
	int	 buflen;

	if ((buflen = asprintf(&buf, "%c%s%c%s", '\0',
		    table_credentials->username, '\0',
		    table_credentials->password)) == -1)
		fatal(NULL);

	if (__b64_ntop((unsigned char *)buf, buflen, dst, size) == -1) {
		free(buf);
		return 0;
	}

	free(buf);
	return 1;
}
