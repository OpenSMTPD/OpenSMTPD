/*	$OpenBSD: mta.c,v 1.148 2012/11/12 14:58:53 eric Exp $	*/

/*
 * Copyright (c) 2008 Pierre-Yves Ritschard <pyr@openbsd.org>
 * Copyright (c) 2008 Gilles Chehade <gilles@openbsd.org>
 * Copyright (c) 2009 Jacek Masiulaniec <jacekm@dobremiasto.net>
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

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <inttypes.h>
#include <netdb.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "smtpd.h"
#include "log.h"

#define MTA_MAXCONN	10	/* connections per relay */
#define MTA_MAXMAIL	100	/* mails per session     */
#define MTA_MAXRCPT	1000	/* rcpt per mail         */

#define MX_MAXCONN	10
#define MX_MAXERROR	5	/* ignore MX after that	 */

struct mta_mxlist {
	struct mta_relay	*relay;
	const char		*error;
	int			 errortype;
	TAILQ_HEAD(, mta_mx)	 mxs;
};

static void mta_imsg(struct imsgev *, struct imsg *);
static void mta_shutdown(void);
static void mta_sig_handler(int, short, void *);

SPLAY_HEAD(mta_relay_tree, mta_relay);
static struct mta_relay *mta_relay_for(struct envelope *);
static void mta_relay_query_mx(struct mta_relay *);
static void mta_relay_query_secret(struct mta_relay *);
static void mta_relay_flush(struct mta_relay *, int, const char *);
static void mta_relay_drain(struct mta_relay *);
static void mta_relay_free(struct mta_relay *);
static int mta_relay_cmp(const struct mta_relay *, const struct mta_relay *);
SPLAY_PROTOTYPE(mta_relay_tree, mta_relay, entry, mta_relay_cmp);

SPLAY_HEAD(mta_host_tree, mta_host);
static struct mta_host *mta_host(const struct sockaddr *);
static void mta_host_unref(struct mta_host *);
static int mta_host_cmp(const struct mta_host *, const struct mta_host *);
SPLAY_PROTOTYPE(mta_host_tree, mta_host, entry, mta_host_cmp);

SPLAY_HEAD(mta_domain_tree, mta_domain);
static struct mta_domain *mta_domain(char *, int);
static void mta_domain_unref(struct mta_domain *);
static int mta_domain_cmp(const struct mta_domain *, const struct mta_domain *);
SPLAY_PROTOTYPE(mta_domain_tree, mta_domain, entry, mta_domain_cmp);

SPLAY_HEAD(mta_source_tree, mta_source);
static struct mta_source *mta_source(const struct sockaddr *);
static void mta_source_unref(struct mta_source *);
static int mta_source_cmp(const struct mta_source *, const struct mta_source *);
SPLAY_PROTOTYPE(mta_source_tree, mta_source, entry, mta_source_cmp);

SPLAY_HEAD(mta_route_tree, mta_route);
static struct mta_route *mta_route(struct mta_source *, struct mta_host *);
static void mta_route_unref(struct mta_route *);
static int mta_route_cmp(const struct mta_route *, const struct mta_route *);
SPLAY_PROTOTYPE(mta_route_tree, mta_route, entry, mta_route_cmp);

static inline uint64_t
ptoid(void * p)
{
	union {
		void	*p;
		uint64_t v;
	} u;

	u.v = 0;
	u.p = p;
	return (u.v);
}

static struct mta_relay_tree	relays;
static struct mta_domain_tree	domains;
static struct mta_host_tree	hosts;
static struct mta_source_tree	sources;
static struct mta_route_tree	routes;

static struct tree batches;

static struct tree wait_mx;
static struct tree wait_preference;
static struct tree wait_secret;

void
mta_imsg(struct imsgev *iev, struct imsg *imsg)
{
	struct dns_resp_msg	*resp_dns;
	struct mta_relay	*relay;
	struct mta_task		*task;
	struct mta_mxlist	*mxl;
	struct mta_mx		*mx, *imx;

	struct tree		*batch;
	struct secret		*secret;
	struct envelope		*e;
	struct ssl		*ssl;
	uint64_t		 id;

	if (iev->proc == PROC_QUEUE) {
		switch (imsg->hdr.type) {

		case IMSG_BATCH_CREATE:
			id = *(uint64_t*)(imsg->data);
			batch = xmalloc(sizeof *batch, "mta_batch");
			tree_init(batch);
			tree_xset(&batches, id, batch);
			log_trace(TRACE_MTA,
			    "mta: batch:%016" PRIx64 " created", id);
			return;

		case IMSG_BATCH_APPEND:
			e = xmemdup(imsg->data, sizeof *e, "mta:envelope");
			relay = mta_relay_for(e);
			batch = tree_xget(&batches, e->batch_id);

			if ((task = tree_get(batch, relay->id)) == NULL) {
				log_trace(TRACE_MTA, "mta: new task for relay "
				    "%s", mta_relay_to_text(relay));
				task = xmalloc(sizeof *task, "mta_task");
				TAILQ_INIT(&task->envelopes);
				task->relay = relay;
				tree_xset(batch, relay->id, task);
				task->msgid = evpid_to_msgid(e->id);
				task->sender = e->sender;
				relay->refcount += 1;
			}

			/* Technically, we could handle that by adding a msg
			 * level, but the batch sent by the scheduler should
			 * be valid.
			 */
			if (task->msgid != evpid_to_msgid(e->id))
				errx(1, "msgid mismatch in batch");

			/* XXX honour relay->maxrcpt */
			TAILQ_INSERT_TAIL(&task->envelopes, e, entry);
			stat_increment("mta.envelope", 1);
			log_debug("debug: mta: received evp:%016" PRIx64
			    " for <%s@%s>",
			    e->id, e->dest.user, e->dest.domain);
			return;

		case IMSG_BATCH_CLOSE:
			id = *(uint64_t*)(imsg->data);
			batch = tree_xpop(&batches, id);
			log_trace(TRACE_MTA, "mta: batch:%016" PRIx64 " closed",
			    id);
			/* for all tasks, queue them on there relay */
			while (tree_poproot(batch, &id, (void**)&task)) {
				if (id != task->relay->id)
					errx(1, "relay id mismatch!");
				task->relay->refcount -= 1;
				task->relay->ntask += 1;
				TAILQ_INSERT_TAIL(&task->relay->tasks, task,
				    entry);
				stat_increment("mta.task", 1);
				mta_relay_drain(task->relay);
			}
			free(batch);
			return;

		case IMSG_QUEUE_MESSAGE_FD:
			mta_session_imsg(iev, imsg);
			return;
		}
	}

	if (iev->proc == PROC_LKA) {
		switch (imsg->hdr.type) {

		case IMSG_LKA_SECRET:
			secret = imsg->data;
			relay = tree_xpop(&wait_secret, secret->id);
			relay->status &= ~RELAY_WAIT_SECRET;
			if (secret->secret[0])
				relay->secret = xstrdup(secret->secret,
				    "mta: secret");
			mta_relay_drain(relay);
			return;

		case IMSG_DNS_HOST:
			resp_dns = imsg->data;
			mxl = tree_xget(&wait_mx, resp_dns->reqid);
			mx = xcalloc(1, sizeof *mx, "mta: mx");
			mx->host = mta_host(
			    (struct sockaddr*)&resp_dns->u.host.ss);
			mx->preference = resp_dns->u.host.preference;
			TAILQ_FOREACH(imx, &mxl->mxs, entry) {
				if (imx->preference >= mx->preference) {
					TAILQ_INSERT_BEFORE(imx, mx, entry);
					return;
				}
			}
			TAILQ_INSERT_TAIL(&mxl->mxs, mx, entry);
			return;

		case IMSG_DNS_HOST_END:
			/* LKA responded to DNS lookup. */
			resp_dns = imsg->data;
			mxl = tree_xpop(&wait_mx, resp_dns->reqid);
			relay = mxl->relay;
			relay->status &= ~RELAY_WAIT_MX;
			if (resp_dns->error == DNS_OK)
				mxl->error = NULL;
			else if (resp_dns->error == DNS_RETRY) {
				mxl->errortype = IMSG_QUEUE_DELIVERY_TEMPFAIL;
				mxl->error = "Temporary failure in MX lookup";
			}
			else if (resp_dns->error == DNS_EINVAL) {
				mxl->errortype = IMSG_QUEUE_DELIVERY_PERMFAIL;
				mxl->error = "Invalid domain name";
			}
			else if (resp_dns->error == DNS_ENONAME) {
				mxl->errortype = IMSG_QUEUE_DELIVERY_PERMFAIL;
				mxl->error = "Domain does not exist";
			}
			else if (resp_dns->error == DNS_ENOTFOUND) {
				mxl->errortype = IMSG_QUEUE_DELIVERY_TEMPFAIL;
				mxl->error = "No MX found for domain";
			}
			else {
				mxl->errortype = IMSG_QUEUE_DELIVERY_TEMPFAIL;
				mxl->error = "Unknown DNS error";
			}
			relay->mxlist = mxl;
			log_debug("debug: MXs for relay %s",
			    mta_relay_to_text(relay));
			TAILQ_FOREACH(mx, &mxl->mxs, entry)
				log_debug("debug: %s -> preference %i",
				    sa_to_text(mx->host->sa), mx->preference);
			log_debug("debug: ---");
			mta_relay_drain(relay);
			return;

		case IMSG_DNS_MX_PREFERENCE:
			/* LKA responded to DNS lookup. */
			resp_dns = imsg->data;
			relay = tree_xpop(&wait_preference, resp_dns->reqid);
			if (resp_dns->error) {
				log_debug("debug: couldn't find backup "
				    "preference for relay %s",
				    mta_relay_to_text(relay));
			}
			else {
				relay->backuppref = resp_dns->u.preference;
				log_debug("debug: found backup preference %i "
				    "for relay %s",
				    relay->backuppref,
				    mta_relay_to_text(relay));
			}
			relay->status &= ~RELAY_WAIT_PREFERENCE;
			mta_relay_drain(relay);
			return;

		case IMSG_DNS_PTR:
			mta_session_imsg(iev, imsg);
			return;
		}
	}

	if (iev->proc == PROC_PARENT) {
		switch (imsg->hdr.type) {
		case IMSG_CONF_START:
			if (env->sc_flags & SMTPD_CONFIGURING)
				return;
			env->sc_flags |= SMTPD_CONFIGURING;
			env->sc_ssl = xcalloc(1, sizeof *env->sc_ssl,
			    "mta:sc_ssl");
			return;

		case IMSG_CONF_SSL:
			if (!(env->sc_flags & SMTPD_CONFIGURING))
				return;
			ssl = xmemdup(imsg->data, sizeof *ssl, "mta:ssl");
			ssl->ssl_cert = xstrdup((char*)imsg->data + sizeof *ssl,
			    "mta:ssl_cert");
			ssl->ssl_key = xstrdup((char*)imsg->data +
			    sizeof *ssl + ssl->ssl_cert_len, "mta:ssl_key");
			SPLAY_INSERT(ssltree, env->sc_ssl, ssl);
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

	errx(1, "mta_imsg: unexpected %s imsg", imsg_to_str(imsg->hdr.type));
}

static void
mta_sig_handler(int sig, short event, void *p)
{
	switch (sig) {
	case SIGINT:
	case SIGTERM:
		mta_shutdown();
		break;
	default:
		fatalx("mta_sig_handler: unexpected signal");
	}
}

static void
mta_shutdown(void)
{
	log_info("info: mail transfer agent exiting");
	_exit(0);
}

pid_t
mta(void)
{
	pid_t		 pid;

	struct passwd	*pw;
	struct event	 ev_sigint;
	struct event	 ev_sigterm;

	struct peer peers[] = {
		{ PROC_PARENT,	imsg_dispatch },
		{ PROC_QUEUE,	imsg_dispatch },
		{ PROC_LKA,	imsg_dispatch },
		{ PROC_CONTROL,	imsg_dispatch }
	};

	switch (pid = fork()) {
	case -1:
		fatal("mta: cannot fork");
	case 0:
		break;
	default:
		return (pid);
	}

	purge_config(PURGE_EVERYTHING);

	pw = env->sc_pw;
	if (chroot(pw->pw_dir) == -1)
		fatal("mta: chroot");
	if (chdir("/") == -1)
		fatal("mta: chdir(\"/\")");

	smtpd_process = PROC_MTA;
	setproctitle("%s", env->sc_title[smtpd_process]);

	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("mta: cannot drop privileges");

	SPLAY_INIT(&relays);
	SPLAY_INIT(&domains);
	SPLAY_INIT(&hosts);
	SPLAY_INIT(&sources);
	SPLAY_INIT(&routes);

	tree_init(&batches);
	tree_init(&wait_secret);
	tree_init(&wait_mx);
	tree_init(&wait_preference);

	imsg_callback = mta_imsg;
	event_init();

	signal_set(&ev_sigint, SIGINT, mta_sig_handler, NULL);
	signal_set(&ev_sigterm, SIGTERM, mta_sig_handler, NULL);
	signal_add(&ev_sigint, NULL);
	signal_add(&ev_sigterm, NULL);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	config_pipes(peers, nitems(peers));
	config_peers(peers, nitems(peers));

	if (event_dispatch() < 0)
		fatal("event_dispatch");
	mta_shutdown();

	return (0);
}

const char *
mta_mx_to_text(struct mta_mx *mx)
{
	static char buf[1024];

	if (mx->host->ptrname)
		snprintf(buf, sizeof buf, "%s [%s]", mx->host->ptrname,
			sa_to_text(mx->host->sa));
	else
		snprintf(buf, sizeof buf, "[%s]", sa_to_text(mx->host->sa));

	return (buf);
}

void
mta_relay_error(struct mta_relay *relay, struct mta_mx *mx, const char *e)
{
	log_info("smtp-out: Error on MX %s: %s", mta_mx_to_text(mx), e);
	if (mx->error++ == MX_MAXERROR)
		log_info("smtp-out: Too many errors on MX %s: ignoring this MX",
		    mta_mx_to_text(mx));
}

void
mta_relay_ok(struct mta_relay *relay, struct mta_mx *mx)
{
	log_debug("debug: mta: %s ready on MX %s", mta_relay_to_text(relay),
	    mta_mx_to_text(mx));
	mx->error = 0;
}

void
mta_relay_collect(struct mta_relay *relay)
{
	relay->nsession -= 1;

	mta_relay_drain(relay);
}

struct mta_mx *
mta_relay_next_mx(struct mta_relay *relay, struct tree *seen)
{
	struct mta_mx	*mx, *best;
	int		 level, limit;

	limit = 0;
	level = -1;
	best = NULL;

	TAILQ_FOREACH(mx, &relay->mxlist->mxs, entry) {

		/* New preference level */		
		if (mx->preference > level) {
			/*
			 * Use the current best if found.
			 */
			if (best)
				break;

			/*
			 * No candidate found.  If there are valid MXs at this
			 * preference level but they reached their limit, just
			 * close the session.
			 */
			if (limit)
				break;

			/*
			 *  If we are a backup MX, do not relay to MXs with
			 *  a greater preference value.
			 */
			if (relay->backuppref != -1 &&
			    mx->preference >= relay->backuppref)
				break;

			/*
			 * Start looking at MXs on this preference level.
			 * Reset the runtime session limit.
			 */ 
			level = mx->preference;
			relay->maxsession = relay->maxconn;
		}

		if (mx->flags & MX_IGNORE)
			continue;

		if (mx->error > MX_MAXERROR)
			continue;

		if (mx->nconn >= MX_MAXCONN) {
			limit = 1;
			continue;
		}

		if (best && mx->nconn >= best->nconn)
			continue;

		if (tree_get(seen, ptoid(mx)))
			continue;

		best = mx;
	}

	if (best) {
		best->nconn++;
		tree_xset(seen, ptoid(best), best);
		return (best);
	}

	/*
	 * We are trying too much on this relay.
	 */
	relay->maxsession = relay->nsession - 1;

	/*
	 * No reachable MX for this relay. Mark it dead for the last session.
	 * This is never true if we hit a limit, because it would mean there
	 * is at least one other session running, so nsession would at least
	 * 2 when this function was called.
	 */
	if (relay->maxsession == 0) {
		relay->status |= RELAY_CLOSED;
		/* Log for the last session only */
		log_info("smtp-out: No reachable MX for relay %s: "
		    "Cancelling all transfers",
		    mta_relay_to_text(relay));
	}

	return (NULL);
}

const char *
mta_relay_to_text(struct mta_relay *relay)
{
	static char	 buf[1024];
	char		 tmp[32];
	const char	*sep = "";

	snprintf(buf, sizeof buf, "%s[", relay->domain->name);

	if (relay->port) {
		snprintf(tmp, sizeof tmp, "port=%i", (int)relay->port);
		strlcat(buf, tmp, sizeof buf);
		sep = ",";
	}

	if (relay->flags & RELAY_STARTTLS) {
		strlcat(buf, sep, sizeof buf);
		sep = ",";
		strlcat(buf, "starttls", sizeof buf);
	}

	if (relay->flags & RELAY_SMTPS) {
		strlcat(buf, sep, sizeof buf);
		sep = ",";
		strlcat(buf, "smtps", sizeof buf);
	}

	if (relay->flags & RELAY_AUTH) {
		strlcat(buf, sep, sizeof buf);
		sep = ",";
		strlcat(buf, "auth=", sizeof buf);
		strlcat(buf, relay->auth, sizeof buf);
	}

	if (relay->cert) {
		strlcat(buf, sep, sizeof buf);
		sep = ",";
		strlcat(buf, "cert=", sizeof buf);
		strlcat(buf, relay->cert, sizeof buf);
	}

	if (relay->flags & RELAY_MX) {
		strlcat(buf, sep, sizeof buf);
		sep = ",";
		strlcat(buf, "mx", sizeof buf);
	}

	if (relay->flags & RELAY_BACKUP) {
		strlcat(buf, sep, sizeof buf);
		strlcat(buf, "backup=", sizeof buf);
		strlcat(buf, relay->backupname, sizeof buf);
	}

	strlcat(buf, "]", sizeof buf);

	return (buf);
}

static struct mta_relay *
mta_relay_for(struct envelope *e)
{
	struct ssl		 ssl;
	struct mta_relay	 key, *relay;

	bzero(&key, sizeof key);

	if (e->agent.mta.relay.flags & RELAY_BACKUP) {
		key.domain = mta_domain(e->dest.domain, 0);
		key.backupname = e->agent.mta.relay.hostname;
	} else if (e->agent.mta.relay.hostname[0]) {
		key.domain = mta_domain(e->agent.mta.relay.hostname, 1);
		key.flags |= RELAY_MX;
	} else {
		key.domain = mta_domain(e->agent.mta.relay.hostname, 0);
	}

	key.flags = e->agent.mta.relay.flags;
	key.port = e->agent.mta.relay.port;
	key.cert = e->agent.mta.relay.cert;
	if (!key.cert[0])
		key.cert = NULL;
	key.auth = e->agent.mta.relay.authtable;
	if (!key.auth[0])
		key.auth = NULL;

	if ((relay = SPLAY_FIND(mta_relay_tree, &relays, &key)) == NULL) {
		relay = xcalloc(1, sizeof *relay, "mta_relay");
		TAILQ_INIT(&relay->tasks);
		relay->id = generate_uid();
		relay->flags = key.flags;
		relay->domain = key.domain;
		relay->backupname = key.backupname ?
		    xstrdup(key.backupname, "mta: backupname") : NULL;
		relay->backuppref = -1;
		relay->port = key.port;
		relay->cert = key.cert ? xstrdup(key.cert, "mta: cert") : NULL;
		relay->auth = key.auth ? xstrdup(key.auth, "mta: auth") : NULL;
		if (relay->cert) {
			strlcpy(ssl.ssl_name, relay->cert,
			    sizeof(ssl.ssl_name));
			relay->ssl = SPLAY_FIND(ssltree, env->sc_ssl, &ssl);
		}
		SPLAY_INSERT(mta_relay_tree, &relays, relay);

		relay->maxconn = MTA_MAXCONN;
		relay->maxmail = MTA_MAXMAIL;
		relay->maxrcpt = MTA_MAXRCPT;

		relay->maxsession = relay->maxconn;

		log_trace(TRACE_MTA, "mta: new relay %s",
		    mta_relay_to_text(relay));
		stat_increment("mta.relay", 1);
		mta_relay_query_mx(relay);
		mta_relay_query_secret(relay);
	} else {
		mta_domain_unref(key.domain);
		log_trace(TRACE_MTA, "mta: reusing relay %s",
		    mta_relay_to_text(relay));
	}

	return (relay);
}

static void
mta_relay_query_secret(struct mta_relay *relay)
{
	struct secret	secret;

	if (relay->auth == NULL)
		return;

	tree_xset(&wait_secret, relay->id, relay);
	relay->status |= RELAY_WAIT_SECRET;

	bzero(&secret, sizeof(secret));
	secret.id = relay->id;
	strlcpy(secret.tablename, relay->auth, sizeof(secret.tablename));
	strlcpy(secret.host, relay->domain->name, sizeof(secret.host));
	imsg_compose_event(env->sc_ievs[PROC_LKA], IMSG_LKA_SECRET,
		    0, 0, -1, &secret, sizeof(secret));
}

static void
mta_relay_query_mx(struct mta_relay *relay)
{
	struct mta_mxlist *mxl;

	mxl = xcalloc(1, sizeof *mxl, "mta: mxlist");
	TAILQ_INIT(&mxl->mxs);
	mxl->relay = relay;
	tree_xset(&wait_mx, relay->id, mxl);
	relay->status |= RELAY_WAIT_MX;

	if (relay->flags & RELAY_MX)
		dns_query_host(relay->id, relay->domain->name);
	else
		dns_query_mx(relay->id, relay->domain->name);

	if (relay->backupname) {
		tree_xset(&wait_preference, relay->id, relay);
		relay->status |= RELAY_WAIT_PREFERENCE;
		dns_query_mx_preference(relay->id, relay->domain->name,
		    relay->backupname);
	}
}



static void
mta_relay_free(struct mta_relay *relay)
{
	struct mta_mx	*mx;

	log_debug("debug: mta: freeing relay %s", mta_relay_to_text(relay));
	SPLAY_REMOVE(mta_relay_tree, &relays, relay);
	if (relay->cert)
		free(relay->cert);
	if (relay->auth)
		free(relay->auth);

	if (relay->mxlist)
		while ((mx = TAILQ_FIRST(&relay->mxlist->mxs))) {
			TAILQ_REMOVE(&relay->mxlist->mxs, mx, entry);
			mta_host_unref(mx->host);
			free(mx);
		}
	mta_domain_unref(relay->domain);
	free(relay);
	stat_decrement("mta.relay", 1);

}

static void
mta_relay_flush(struct mta_relay *relay, int fail, const char *error)
{
	struct envelope	*e;
	struct mta_task	*task;
	const char	*pfx;
	char		 buf[MAX_LINE_SIZE];
	size_t		 n;

	if (fail == IMSG_QUEUE_DELIVERY_TEMPFAIL)
		pfx = "TempFail";
	else if (fail == IMSG_QUEUE_DELIVERY_PERMFAIL)
		pfx = "PermFail";
	else
		errx(1, "unexpected delivery status %i", fail);

	snprintf(buf, sizeof buf, "relay=%s, ", relay->domain->name);

	n = 0;
	while ((task = TAILQ_FIRST(&relay->tasks))) {
		TAILQ_REMOVE(&relay->tasks, task, entry);
		while ((e = TAILQ_FIRST(&task->envelopes))) {
			TAILQ_REMOVE(&task->envelopes, e, entry);
			envelope_set_errormsg(e, "%s", error);
			log_envelope(e, buf, pfx, e->errorline);
			imsg_compose_event(env->sc_ievs[PROC_QUEUE], fail,
			    0, 0, -1, e, sizeof(*e));
			free(e);
			n++;
		}
		free(task);
	}

	stat_decrement("mta.task", relay->ntask);
	stat_decrement("mta.envelope", n);
	relay->ntask = 0;
}

static void
mta_relay_drain(struct mta_relay *relay)
{
	char		 buf[64];

	log_debug("debug: mta: draining relay %s "
	    "(tasks=%i, refs=%i, sessions=%i/%i)",
	    mta_relay_to_text(relay),
	    relay->ntask, relay->refcount, relay->nsession, relay->maxsession);

	/* Wait until we are ready to proceed */
	if (relay->status & RELAY_WAITMASK) {
		buf[0] = '\0';
		if (relay->status & RELAY_WAIT_MX)
			strlcat(buf, "MX ", sizeof buf);
		if (relay->status & RELAY_WAIT_PREFERENCE)
			strlcat(buf, "preference ", sizeof buf);
		if (relay->status & RELAY_WAIT_SECRET)
			strlcat(buf, "secret ", sizeof buf);
		log_debug("debug: mta: relay %s waiting for %s",
		    mta_relay_to_text(relay), buf);
		return;
	}

	if (relay->auth && relay->secret == NULL) {
		log_warnx("warn: Failed to retreive secret for relay %s",
		    mta_relay_to_text(relay));
		mta_relay_flush(relay, IMSG_QUEUE_DELIVERY_TEMPFAIL,
		    "Cannot retreive secret");
		if (relay->refcount == 0)
			mta_relay_free(relay);
		return;
	}

	if (relay->mxlist->error) {
		log_info("smtp-out: Failed to resolve MX for relay %s: %s",
		    mta_relay_to_text(relay), relay->mxlist->error);
		mta_relay_flush(relay, relay->mxlist->errortype,
		    relay->mxlist->error);
		if (relay->refcount == 0)
			mta_relay_free(relay);
		return;
	}

	if (relay->ntask == 0) {
		log_debug("debug: mta: all done for relay %s",
		    mta_relay_to_text(relay));
		if (relay->refcount == 0 && relay->nsession == 0)
			mta_relay_free(relay);
		return;
	}

	if (relay->status & RELAY_CLOSED) {
		mta_relay_flush(relay, IMSG_QUEUE_DELIVERY_TEMPFAIL,
		    "No reachable MX");
		if (relay->refcount == 0 && relay->nsession == 0)
			mta_relay_free(relay);
		return;
	}

	/* Make sure there is one session for each task */
	while (relay->nsession < relay->ntask) {
		/*
		 * If we have reached the max number of session, just wait
		 */
		if (relay->nsession >= relay->maxsession) {
			log_debug("debug: mta: max conn reached for relay %s",
			    mta_relay_to_text(relay));
			return;
		}
		relay->nsession += 1;
		mta_session(relay);
	}
}

static int
mta_relay_cmp(const struct mta_relay *a, const struct mta_relay *b)
{
	int	r;

	if (a->domain < b->domain)
		return (-1);
	if (a->domain > b->domain)
		return (1);

	if (a->flags < b->flags)
		return (-1);
	if (a->flags > b->flags)
		return (1);

	if (a->port < b->port)
		return (-1);
	if (a->port > b->port)
		return (1);

	if (a->auth == NULL && b->auth)
		return (-1);
	if (a->auth && b->auth == NULL)
		return (1);
	if (a->auth && ((r = strcmp(a->auth, b->auth))))
		return (r);

	if (a->cert == NULL && b->cert)
		return (-1);
	if (a->cert && b->cert == NULL)
		return (1);
	if (a->cert && ((r = strcmp(a->cert, b->cert))))
		return (r);

	if (a->backupname && ((r = strcmp(a->backupname, b->backupname))))
		return (r);

	return (0);
}

SPLAY_GENERATE(mta_relay_tree, mta_relay, entry, mta_relay_cmp);

static struct mta_host *
mta_host(const struct sockaddr *sa)
{
	struct mta_host		key, *h;
	struct sockaddr_storage	ss;

	memmove(&ss, sa, sa->sa_len);
	key.sa = (struct sockaddr*)&ss;
	h = SPLAY_FIND(mta_host_tree, &hosts, &key);

	if (h == NULL) {
		h = xcalloc(1, sizeof(*h), "mta_host");
		h->sa = xmemdup(sa, sa->sa_len, "mta_host");
		SPLAY_INSERT(mta_host_tree, &hosts, h);
		stat_increment("mta.host", 1);
	}

	h->refcount++;
	return (h);
}

static void
mta_host_unref(struct mta_host *h)
{
	if (--h->refcount)
		return;

	SPLAY_REMOVE(mta_host_tree, &hosts, h);
	free(h->sa);
	free(h->ptrname);
	stat_decrement("mta.host", 1);
}

static int
mta_host_cmp(const struct mta_host *a, const struct mta_host *b)
{
	if (a->sa->sa_len < b->sa->sa_len)
		return (-1);
	if (a->sa->sa_len > b->sa->sa_len)
		return (1);
	return (memcmp(a->sa, b->sa, a->sa->sa_len));
}

SPLAY_GENERATE(mta_host_tree, mta_host, entry, mta_host_cmp);

static struct mta_domain *
mta_domain(char *name, int flags)
{
	struct mta_domain	key, *d;

	key.name = name;
	key.flags = flags;
	d = SPLAY_FIND(mta_domain_tree, &domains, &key);

	if (d == NULL) {
		d = xcalloc(1, sizeof(*d), "mta_domain");
		d->name = xstrdup(name, "mta_domain");
		d->flags = flags;
		TAILQ_INIT(&d->mxs);
		SPLAY_INSERT(mta_domain_tree, &domains, d);
		stat_increment("mta.domain", 1);
	}

	d->refcount++;
	return (d);
}

static void
mta_domain_unref(struct mta_domain *d)
{
	if (--d->refcount)
		return;

	SPLAY_REMOVE(mta_domain_tree, &domains, d);
	free(d->name);
	stat_decrement("mta.domain", 1);
}

static int
mta_domain_cmp(const struct mta_domain *a, const struct mta_domain *b)
{
	if (a->flags < b->flags)
		return (-1);
	if (a->flags > b->flags)
		return (1);
	return (strcasecmp(a->name, b->name));
}

SPLAY_GENERATE(mta_domain_tree, mta_domain, entry, mta_domain_cmp);

static struct mta_source *
mta_source(const struct sockaddr *sa)
{
	struct mta_source	key, *s;
	struct sockaddr_storage	ss;

	if (sa) {
		memmove(&ss, sa, sa->sa_len);
		key.sa = (struct sockaddr*)&ss;
	} else
		key.sa = NULL;
	s = SPLAY_FIND(mta_source_tree, &sources, &key);

	if (s == NULL) {
		s = xcalloc(1, sizeof(*s), "mta_source");
		if (sa)
			s->sa = xmemdup(sa, sa->sa_len, "mta_source");
		SPLAY_INSERT(mta_source_tree, &sources, s);
		stat_increment("mta.source", 1);
	}

	s->refcount++;
	return (s);
}

static void
mta_source_unref(struct mta_source *s)
{
	if (--s->refcount)
		return;

	SPLAY_REMOVE(mta_source_tree, &sources, s);
	free(s->sa);
	stat_decrement("mta.source", 1);
}

static int
mta_source_cmp(const struct mta_source *a, const struct mta_source *b)
{
	if (a->sa == NULL)
		return ((b->sa == NULL) ? 0 : -1);
	if (b->sa == NULL)
		return (1);
	if (a->sa->sa_len < b->sa->sa_len)
		return (-1);
	if (a->sa->sa_len > b->sa->sa_len)
		return (1);
	return (memcmp(a->sa, b->sa, a->sa->sa_len));
}

SPLAY_GENERATE(mta_source_tree, mta_source, entry, mta_source_cmp);

static struct mta_route *
mta_route(struct mta_source *src, struct mta_host *dst)
{
	struct mta_route	key, *r;

	key.src = src;
	key.dst = dst;
	r = SPLAY_FIND(mta_route_tree, &routes, &key);

	if (r == NULL) {
		r = xcalloc(1, sizeof(*r), "mta_route");
		r->src = src;
		r->dst = dst;
		SPLAY_INSERT(mta_route_tree, &routes, r);
		src->refcount++;
		dst->refcount++;
		stat_increment("mta.route", 1);
	}

	r->refcount++;
	return (r);
}

static void
mta_route_unref(struct mta_route *r)
{
	if (--r->refcount)
		return;

	SPLAY_REMOVE(mta_route_tree, &routes, r);
	mta_source_unref(r->src);
	mta_host_unref(r->dst);
	stat_decrement("mta.route", 1);
}

static int
mta_route_cmp(const struct mta_route *a, const struct mta_route *b)
{
	if (a->src < b->src)
		return (-1);
	if (a->src > b->src)
		return (1);

	if (a->dst < b->dst)
		return (-1);
	if (a->dst > b->dst)
		return (1);

	return (0);
}

SPLAY_GENERATE(mta_route_tree, mta_route, entry, mta_route_cmp);
