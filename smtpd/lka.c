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

#include "includes.h"

#include <sys/types.h>
#include "sys-queue.h"
#include "sys-tree.h"
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <netinet/in.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <event.h>
#include <netdb.h>
#include <grp.h> /* needed for setgroups */
#include "imsg.h"
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
static int lka_encode_credentials(char *, size_t, struct credentials *);

static void
lka_imsg(struct imsgev *iev, struct imsg *imsg)
{
	struct lka_expand_msg	*req;
	struct auth		*auth;
	struct secret		*secret;
	struct rule		*rule;
	struct table		*table;
	void			*tmp;
	int			ret;
	const char		*k;
	const char		*v;
	static struct dict	*tables_dict;
	static struct tree	*tables_tree;
	static struct table	*table_last;
	struct credentials	*creds;

	if (imsg->hdr.type == IMSG_DNS_HOST ||
	    imsg->hdr.type == IMSG_DNS_PTR ||
	    imsg->hdr.type == IMSG_DNS_MX ||
	    imsg->hdr.type == IMSG_DNS_MX_PREFERENCE) {
		dns_imsg(iev, imsg);
		return;
	}

	if (iev->proc == PROC_SMTP) {
		switch (imsg->hdr.type) {
		case IMSG_LKA_EXPAND_RCPT:
			req = imsg->data;
			lka_session(req->reqid, &req->evp);
			return;
		case IMSG_LKA_AUTHENTICATE:
			auth = imsg->data;

			if (! auth->authtable[0]) {
				imsg_compose_event(env->sc_ievs[PROC_PARENT],
				    IMSG_LKA_AUTHENTICATE, 0, 0, -1, auth, sizeof(*auth));
				return;
			}

			log_debug("looking for user %s in auth table: %s",
			    auth->user, auth->authtable);

			table = table_findbyname(auth->authtable);
			if (table == NULL)
				auth->success = 0;
			else {
				switch (table_lookup(table, auth->user, K_CREDENTIALS, (void **)&creds)) {
				case -1:
					auth->success = 0;
					break;
				case 0:
					auth->success = 0;
					break;
				default:
					auth->success = 0;
					if (! strcmp(creds->password, crypt(auth->pass, creds->password)))
						auth->success = 1;
					break;
				}
			}

			imsg_compose_event(env->sc_ievs[PROC_SMTP],
			    IMSG_LKA_AUTHENTICATE, 0, 0, -1, auth, sizeof(*auth));
			return;
		}
	}

	if (iev->proc == PROC_MDA) {
		switch (imsg->hdr.type) {
		case IMSG_LKA_USERINFO: {
			struct userinfo		       *userinfo = NULL;
			struct lka_userinfo_req_msg    *lka_userinfo_req = imsg->data;
			struct lka_userinfo_resp_msg	lka_userinfo_resp;

			strlcpy(lka_userinfo_resp.username, lka_userinfo_req->username,
			    sizeof lka_userinfo_resp.username);
			strlcpy(lka_userinfo_resp.usertable, lka_userinfo_req->usertable,
			    sizeof lka_userinfo_resp.usertable);

			table = table_findbyname(lka_userinfo_req->usertable);
			if (table == NULL)
				lka_userinfo_resp.status = LKA_TEMPFAIL;
			else {
				switch (table_lookup(table, lka_userinfo_req->username, K_USERINFO, (void **)&userinfo)) {
				case -1:
					lka_userinfo_resp.status = LKA_TEMPFAIL;
					break;
				case 0:
					lka_userinfo_resp.status = LKA_PERMFAIL;
					break;
				default:
					lka_userinfo_resp.status = LKA_OK;
					lka_userinfo_resp.userinfo = *userinfo;
					break;
				}
			}
			imsg_compose_event(iev, IMSG_LKA_USERINFO, 0, 0, -1,
			    &lka_userinfo_resp, sizeof lka_userinfo_resp);
			free(userinfo);
			return;
		}
		}
	}

	if (iev->proc == PROC_MTA) {
		switch (imsg->hdr.type) {
		case IMSG_LKA_SECRET: {
			struct credentials *credentials = NULL;

			secret = imsg->data;
			table = table_findbyname(secret->tablename);
			if (table == NULL) {
				log_warn("warn: Credentials table %s missing",
				    secret->tablename);
				imsg_compose_event(iev, IMSG_LKA_SECRET, 0, 0,
				    -1, secret, sizeof *secret);
				return;
			}
			ret = table_lookup(table, secret->label, K_CREDENTIALS,
			    (void **)&credentials);

			log_debug("debug: lka: %s credentials lookup (%d)",
			    secret->label, ret);

			/*
			  log_debug("k:%s, v:%s", credentials->username,
			  credentials->password);
			*/
			secret->secret[0] = '\0';
			if (ret == -1)
				log_warnx("warn: Credentials lookup fail for "
				    "%s", secret->label);
			else if (ret == 0)
				log_debug("debug: %s credentials not found",
				    secret->label);
			else if (lka_encode_credentials(secret->secret,
				sizeof secret->secret, credentials) == 0)
				log_warnx("warn: Credentials parse error for "
				    "%s", secret->label);
			imsg_compose_event(iev, IMSG_LKA_SECRET, 0, 0, -1,
			    secret, sizeof *secret);
			free(credentials);
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

		case IMSG_CONF_RULE_DESTINATION:
			rule = TAILQ_LAST(env->sc_rules_reload, rulelist);
			tmp = env->sc_tables_dict;
			env->sc_tables_dict = tables_dict;
			rule->r_destination = table_findbyname(imsg->data);
			if (rule->r_destination == NULL)
				fatalx("lka: tables inconsistency");
			env->sc_tables_dict = tmp;
			return;

		case IMSG_CONF_RULE_MAPPING:
			rule = TAILQ_LAST(env->sc_rules_reload, rulelist);
			tmp = env->sc_tables_dict;
			env->sc_tables_dict = tables_dict;
			rule->r_mapping = table_findbyname(imsg->data);
			if (rule->r_mapping == NULL)
				fatalx("lka: tables inconsistency");
			env->sc_tables_dict = tmp;
			return;

		case IMSG_CONF_RULE_USERS:
			rule = TAILQ_LAST(env->sc_rules_reload, rulelist);
			tmp = env->sc_tables_dict;
			env->sc_tables_dict = tables_dict;
			rule->r_users = table_findbyname(imsg->data);
			if (rule->r_users == NULL)
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
			event_add(&env->sc_ievs[PROC_SMTP]->ev, NULL);
			return;

		case IMSG_CTL_VERBOSE:
			log_verbose(*(int *)imsg->data);
			return;

		case IMSG_PARENT_FORWARD_OPEN:
			lka_session_forward_reply(imsg->data, imsg->fd);
			return;
		case IMSG_LKA_AUTHENTICATE:
			auth = imsg->data;
			imsg_compose_event(env->sc_ievs[PROC_SMTP],
			    IMSG_LKA_AUTHENTICATE, 0, 0, -1, auth, sizeof(*auth));
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
#ifdef VALGRIND
	child_free();
	free_peers();
	clean_setproctitle();
	event_base_free(NULL);
#endif
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
		{ PROC_QUEUE,	imsg_dispatch },
		{ PROC_SMTP,	imsg_dispatch },
		{ PROC_MDA,	imsg_dispatch },
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
	event_del(&env->sc_ievs[PROC_SMTP]->ev);

	if (event_dispatch() < 0)
		fatal("event_dispatch");
	lka_shutdown();

	return (0);
}

static int
lka_encode_credentials(char *dst, size_t size,
    struct credentials *credentials)
{
	char	*buf;
	int	 buflen;

	if ((buflen = asprintf(&buf, "%c%s%c%s", '\0',
		    credentials->username, '\0',
		    credentials->password)) == -1)
		fatal(NULL);

	if (__b64_ntop((unsigned char *)buf, buflen, dst, size) == -1) {
		free(buf);
		return 0;
	}

	free(buf);
	return 1;
}
