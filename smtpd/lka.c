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
#include <sys/uio.h>

#include <netinet/in.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <pwd.h>
#include <resolv.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "smtpd.h"
#include "log.h"

static void lka_imsg(struct mproc *, struct imsg *);
static void lka_shutdown(void);
static void lka_sig_handler(int, short, void *);
static int lka_encode_credentials(char *, size_t, struct credentials *);
static int lka_X509_verify(X509 *, const char *, const char *, const char **);

static void
lka_imsg(struct mproc *p, struct imsg *imsg)
{
	struct lka_expand_msg		*req;
	struct lka_source_req_msg	*req_source;
	struct lka_source_resp_msg	 resp;
	struct auth		*auth;
	struct secret		*secret;
	struct rule		*rule;
	struct table		*table;
	void			*tmp;
	int			ret;
	const char		*k, *v;
	char			*src;
	static struct dict	*ssl_dict;
	static struct dict	*tables_dict;
	static struct tree	*tables_tree;
	static struct table	*table_last;
	struct credentials	*creds;
	struct ca_cert_req_msg	*req_ca_cert;
	struct ca_cert_resp_msg	resp_ca_cert;
	struct ca_vrfy_req_msg	*req_ca_vrfy;
	struct ca_vrfy_resp_msg	resp_ca_vrfy;
	struct ssl		*ssl;
	struct iovec		iov[3];
	X509		        *x;
	const unsigned char    	*d2i;
	const char	        *errstr = NULL;

	if (imsg->hdr.type == IMSG_DNS_HOST ||
	    imsg->hdr.type == IMSG_DNS_PTR ||
	    imsg->hdr.type == IMSG_DNS_MX ||
	    imsg->hdr.type == IMSG_DNS_MX_PREFERENCE) {
		dns_imsg(p, imsg);
		return;
	}

	if (p->proc == PROC_SMTP) {
		switch (imsg->hdr.type) {
		case IMSG_LKA_EXPAND_RCPT:
			req = imsg->data;
			lka_session(req->reqid, &req->evp);
			return;

		case IMSG_LKA_SSL_INIT:
			req_ca_cert = imsg->data;
			resp_ca_cert.reqid = req_ca_cert->reqid;

			ssl = dict_get(env->sc_ssl_dict, req_ca_cert->name);
			if (ssl == NULL) {
				resp_ca_cert.status = CA_FAIL;
				m_compose(p, IMSG_LKA_SSL_INIT, 0, 0, -1, &resp_ca_cert,
				    sizeof(resp_ca_cert));
				return;
			}
			resp_ca_cert.status = CA_OK;
			resp_ca_cert.cert_len = ssl->ssl_cert_len;
			resp_ca_cert.key_len = ssl->ssl_key_len;
			iov[0].iov_base = &resp_ca_cert;
			iov[0].iov_len = sizeof(resp_ca_cert);
			iov[1].iov_base = ssl->ssl_cert;
			iov[1].iov_len = ssl->ssl_cert_len;
			iov[2].iov_base = ssl->ssl_key;
			iov[2].iov_len = ssl->ssl_key_len;
			m_composev(p, IMSG_LKA_SSL_INIT, 0, 0, -1, iov, nitems(iov));
			return;

		case IMSG_LKA_SSL_VERIFY:
			req_ca_vrfy = xmemdup(imsg->data, sizeof *req_ca_vrfy, "lka:ca_vrfy");
			if (req_ca_vrfy == NULL)
				fatal(NULL);
			req_ca_vrfy->cert = xmemdup((char *)imsg->data +
			    sizeof *req_ca_vrfy, req_ca_vrfy->cert_len, "lka:ca_vrfy");

			resp_ca_vrfy.reqid = req_ca_vrfy->reqid;
			resp_ca_vrfy.status = CA_FAIL;

			x = NULL;
			d2i = req_ca_vrfy->cert;
			d2i_X509(&x, &d2i, req_ca_vrfy->cert_len);

			if (! lka_X509_verify(x, "/etc/ssl/cert.pem", NULL, &errstr))
				resp_ca_vrfy.status = CA_FAIL;
			else
				resp_ca_vrfy.status = CA_OK;

			if (x)
				X509_free(x);

			m_compose(p, IMSG_LKA_SSL_VERIFY, 0, 0, -1, &resp_ca_vrfy,
			    sizeof resp_ca_vrfy);

			free(req_ca_vrfy->cert);
			free(req_ca_vrfy);
			return;

		case IMSG_LKA_AUTHENTICATE:
			auth = imsg->data;

			if (! auth->authtable[0]) {
				m_compose(p_parent, IMSG_LKA_AUTHENTICATE,
				    0, 0, -1, auth, sizeof(*auth));
				return;
			}

			log_debug("looking for user %s in auth table: %s",
			    auth->user, auth->authtable);

			table = table_findbyname(auth->authtable);
			if (table == NULL) {
				log_warnx("warn: could not find table %s needed for authentication",
					auth->authtable);
				auth->success = -1;
			}
			else {
				switch (table_lookup(table, auth->user, K_CREDENTIALS, (void **)&creds)) {
				case -1:
					auth->success = -1;
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
			m_compose(p_smtp, IMSG_LKA_AUTHENTICATE, 0, 0, -1,
			    auth, sizeof(*auth));
			return;
		}
	}

	if (p->proc == PROC_MDA) {
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
			m_compose(p, IMSG_LKA_USERINFO, 0, 0, -1,
			    &lka_userinfo_resp, sizeof lka_userinfo_resp);
			free(userinfo);
			return;
		}
		}
	}

	if (p->proc == PROC_MTA) {
		switch (imsg->hdr.type) {
		case IMSG_LKA_SECRET: {
			struct credentials *credentials = NULL;

			secret = imsg->data;
			table = table_findbyname(secret->tablename);
			if (table == NULL) {
				log_warn("warn: Credentials table %s missing",
				    secret->tablename);
				m_compose(p, IMSG_LKA_SECRET, 0, 0, -1,
				    secret, sizeof *secret);
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
			m_compose(p, IMSG_LKA_SECRET, 0, 0, -1,
			    secret, sizeof *secret);
			free(credentials);
			return;
		}
		case IMSG_LKA_SOURCE:
			req_source = imsg->data;
			resp.reqid = req_source->reqid;
			table = table_findbyname(req_source->tablename);
			if (table == NULL) {
				log_warn("warn: source address table %s missing",
				    req_source->tablename);
				resp.status = LKA_TEMPFAIL;
			} 
			else {
				ret = table_fetch(table, K_SOURCE, &src);
				if (ret == -1)
					resp.status = LKA_TEMPFAIL;
				else if (ret == 0)
					resp.status = LKA_PERMFAIL;
				else {
					struct addrinfo	hints, *ai;
					log_debug("debug: source: %s", src);
					resp.status = LKA_OK;
					/* XXX find a nicer way? */
					bzero(&hints, sizeof hints);
					hints.ai_flags = AI_NUMERICHOST;
					getaddrinfo(src, NULL, &hints, &ai);
					memmove(&resp.ss, ai->ai_addr,
					    ai->ai_addrlen);
					freeaddrinfo(ai);
					free(src);
				}
			}
			m_compose(p, IMSG_LKA_SOURCE, 0, 0, -1,
			    &resp, sizeof resp);
			return;
		}
	}

	if (p->proc == PROC_PARENT) {
		switch (imsg->hdr.type) {
		case IMSG_CONF_START:
			env->sc_rules_reload = xcalloc(1,
			    sizeof *env->sc_rules, "lka:sc_rules_reload");
			tables_dict = xcalloc(1,
			    sizeof *tables_dict, "lka:tables_dict");
			tables_tree = xcalloc(1,
			    sizeof *tables_tree, "lka:tables_tree");

			ssl_dict = calloc(1, sizeof *ssl_dict);
			if (ssl_dict == NULL)
				fatal(NULL);
			dict_init(ssl_dict);
			dict_init(tables_dict);
			tree_init(tables_tree);
			TAILQ_INIT(env->sc_rules_reload);

			return;

		case IMSG_CONF_SSL:
			ssl = calloc(1, sizeof *ssl);
			if (ssl == NULL)
				fatal(NULL);
			*ssl = *(struct ssl *)imsg->data;
			ssl->ssl_cert = xstrdup((char *)imsg->data +
			    sizeof *ssl, "smtp:ssl_cert");
			ssl->ssl_key = xstrdup((char *)imsg->data +
			    sizeof *ssl + ssl->ssl_cert_len, "smtp:ssl_key");
			if (ssl->ssl_dhparams_len) {
				ssl->ssl_dhparams = xstrdup((char *)imsg->data
				    + sizeof *ssl + ssl->ssl_cert_len +
				    ssl->ssl_key_len, "smtp:ssl_dhparams");
			}
			if (ssl->ssl_ca_len) {
				ssl->ssl_ca = xstrdup((char *)imsg->data
				    + sizeof *ssl + ssl->ssl_cert_len +
				    ssl->ssl_key_len + ssl->ssl_dhparams_len,
				    "smtp:ssl_ca");
			}
			dict_set(ssl_dict, ssl->ssl_name, ssl);
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
			env->sc_ssl_dict = ssl_dict;
			env->sc_tables_dict = tables_dict;
			env->sc_tables_tree = tables_tree;
			table_open_all();

			ssl_dict = NULL;
			table_last = NULL;
			tables_dict = NULL;
			tables_tree = NULL;

			/* Start fulfilling requests */
			mproc_enable(p_mda);
			mproc_enable(p_mta);
			mproc_enable(p_smtp);
			return;

		case IMSG_CTL_VERBOSE:
			log_verbose(*(int *)imsg->data);
			return;

		case IMSG_PARENT_FORWARD_OPEN:
			lka_session_forward_reply(imsg->data, imsg->fd);
			return;
		case IMSG_LKA_AUTHENTICATE:
			auth = imsg->data;
			m_compose(p_smtp,  IMSG_LKA_AUTHENTICATE, 0, 0, -1,
			    auth, sizeof(*auth));
			return;
		}
	}

	if (p->proc == PROC_CONTROL) {
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

	config_peer(PROC_PARENT);
	config_peer(PROC_QUEUE);
	config_peer(PROC_SMTP);
	config_peer(PROC_MDA);
	config_peer(PROC_MTA);
	config_peer(PROC_CONTROL);
	config_done();

	/* Ignore them until we get our config */
	mproc_disable(p_mda);
	mproc_disable(p_mta);
	mproc_disable(p_smtp);

	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

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

static int
lka_X509_verify(X509 *certificate, const char *CAfile, const char *CRLfile, const char **errstr)
{
	X509_STORE	*store = NULL;
	X509_LOOKUP	*lookup = NULL;
	X509_STORE_CTX	*xsc = NULL;
	int		i = 0;

	if ((store = X509_STORE_new()) == NULL)
		goto end;

	if (CAfile) {
//		if ((lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file())) == NULL)
//			goto end;
		
		log_debug("CAfile: %s", CAfile);
//		if (! X509_LOOKUP_load_file(lookup, CAfile, X509_FILETYPE_PEM))
//			goto end;
//
		if ((lookup = X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir())) == NULL)
			goto end;

		X509_LOOKUP_add_dir(lookup, "/etc/ssl", X509_FILETYPE_PEM);
	}

	if ((xsc = X509_STORE_CTX_new()) == NULL)
		goto end;

	if (! X509_STORE_CTX_init(xsc, store, certificate, 0))
		goto end;

	i = X509_verify_cert(xsc);

	log_debug("DID THE VERIF");

end:
	log_debug("i == %d", i);
	*errstr = NULL;
	if (i <= 0) {
		if (ERR_peek_last_error())
			*errstr = ERR_error_string(ERR_peek_last_error(), NULL);
	}

	if (xsc)
		X509_STORE_CTX_free(xsc);
	if (store)
		X509_STORE_free(store);
	return i > 0 ? 1 : 0;
}
