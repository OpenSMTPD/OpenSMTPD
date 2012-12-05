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

#define MTA_MAXCONN	10	/* connections per route */
#define MTA_MAXMAIL	100	/* mails per session     */
#define MTA_MAXRCPT	1000	/* rcpt per mail         */

#define MX_MAXCONN	10
#define MX_MAXERROR	5	/* ignore MX after that	 */

struct mta_mxlist {
	struct mta_route	*route;
	const char		*error;
	int			 errortype;
	TAILQ_HEAD(, mta_mx)	 mxs;
};

static void mta_imsg(struct imsgev *, struct imsg *);
static void mta_shutdown(void);
static void mta_sig_handler(int, short, void *);

SPLAY_HEAD(mta_route_tree, mta_route);
static struct mta_route *mta_route_for(struct envelope *);
static void mta_route_query_mx(struct mta_route *);
static void mta_route_query_secret(struct mta_route *);
static void mta_route_flush(struct mta_route *, int, const char *);
static void mta_route_drain(struct mta_route *);
static void mta_route_free(struct mta_route *);
static int mta_route_cmp(const struct mta_route *, const struct mta_route *);
SPLAY_PROTOTYPE(mta_route_tree, mta_route, entry, mta_route_cmp);

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

static struct mta_route_tree	routes;
static struct mta_domain_tree	domains;
static struct mta_host_tree	hosts;

static struct tree batches;

static struct tree wait_mx;
static struct tree wait_preference;
static struct tree wait_secret;

void
mta_imsg(struct imsgev *iev, struct imsg *imsg)
{
	struct dns_resp_msg	*resp_dns;
	struct mta_route	*route;
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
			route = mta_route_for(e);
			batch = tree_xget(&batches, e->batch_id);

			if ((task = tree_get(batch, route->id)) == NULL) {
				log_trace(TRACE_MTA, "mta: new task for route "
				   "%s", mta_route_to_text(route));
				task = xmalloc(sizeof *task, "mta_task");
				TAILQ_INIT(&task->envelopes);
				task->route = route;
				tree_xset(batch, route->id, task);
				task->msgid = evpid_to_msgid(e->id);
				task->sender = e->sender;
				route->refcount += 1;
			}

			/* Technically, we could handle that by adding a msg
			 * level, but the batch sent by the scheduler should
			 * be valid.
			 */
			if (task->msgid != evpid_to_msgid(e->id))
				errx(1, "msgid mismatch in batch");

			/* XXX honour route->maxrcpt */
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
			/* for all tasks, queue them on there route */
			while (tree_poproot(batch, &id, (void**)&task)) {
				if (id != task->route->id)
					errx(1, "route id mismatch!");
				task->route->refcount -= 1;
				task->route->ntask += 1;
				TAILQ_INSERT_TAIL(&task->route->tasks, task,
				    entry);
				stat_increment("mta.task", 1);
				mta_route_drain(task->route);
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
			route = tree_xpop(&wait_secret, secret->id);
			route->status &= ~ROUTE_WAIT_SECRET;
			if (secret->secret[0])
				route->secret = xstrdup(secret->secret,
				    "mta: secret");
			mta_route_drain(route);
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
			route = mxl->route;
			route->status &= ~ROUTE_WAIT_MX;
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
			route->mxlist = mxl;
			log_debug("debug: MXs for route %s",
			    mta_route_to_text(route));
			TAILQ_FOREACH(mx, &mxl->mxs, entry)
				log_debug("debug: %s -> preference %i",
				    sa_to_text(mx->host->sa), mx->preference);
			log_debug("debug: ---");
			mta_route_drain(route);
			return;

		case IMSG_DNS_MX_PREFERENCE:
			/* LKA responded to DNS lookup. */
			resp_dns = imsg->data;
			route = tree_xpop(&wait_preference, resp_dns->reqid);
			if (resp_dns->error) {
				log_debug("debug: couldn't find backup "
				    "preference for route %s",
				    mta_route_to_text(route));
			}
			else {
				route->backuppref = resp_dns->u.preference;
				log_debug("debug: found backup preference %i "
				    "for route %s",
				    route->backuppref,
				    mta_route_to_text(route));
			}
			route->status &= ~ROUTE_WAIT_PREFERENCE;
			mta_route_drain(route);
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

	SPLAY_INIT(&routes);
	SPLAY_INIT(&domains);
	SPLAY_INIT(&hosts);
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
mta_route_error(struct mta_route *route, struct mta_mx *mx, const char *e)
{
	log_info("smtp-out: Error on MX %s: %s", mta_mx_to_text(mx), e);
	if (mx->error++ == MX_MAXERROR)
		log_info("smtp-out: Too many errors on MX %s: ignoring this MX",
		    mta_mx_to_text(mx));
}

void
mta_route_ok(struct mta_route *route, struct mta_mx *mx)
{
	log_debug("debug: mta: %s ready on MX %s", mta_route_to_text(route),
	    mta_mx_to_text(mx));
	mx->error = 0;
}

void
mta_route_collect(struct mta_route *route)
{
	route->nsession -= 1;

	mta_route_drain(route);
}

struct mta_mx *
mta_route_next_mx(struct mta_route *route, struct tree *seen)
{
	struct mta_mx	*mx, *best;
	int		 level, limit;
	union {
		uint64_t v;
		void	*p;
	} u;


	limit = 0;
	level = -1;
	best = NULL;

	TAILQ_FOREACH(mx, &route->mxlist->mxs, entry) {

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
			if (route->backuppref != -1 &&
			    mx->preference >= route->backuppref)
				break;

			/*
			 * Start looking at MXs on this preference level.
			 * Reset the runtime session limit.
			 */ 
			level = mx->preference;
			route->maxsession = route->maxconn;
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

		u.v = 0;
		u.p = mx;
		if (tree_get(seen, u.v))
			continue;

		best = mx;
	}

	if (best) {
		best->nconn++;
		u.v = 0;
		u.p = best;
		tree_xset(seen, u.v, best);
		return (best);
	}

	/*
	 * We are trying too much on this route.
	 */
	route->maxsession = route->nsession - 1;

	/*
	 * No reachable MX for this route. Mark it dead for the last session.
	 * This is never true if we hit a limit, because it would mean there
	 * is at least one other session running, so nsession would at least
	 * 2 when this function was called.
	 */
	if (route->maxsession == 0) {
		route->status |= ROUTE_CLOSED;
		/* Log for the last session only */
		log_info("smtp-out: No reachable MX for route %s: "
		    "Cancelling all transfers",
		    mta_route_to_text(route));
	}

	return (NULL);
}

const char *
mta_route_to_text(struct mta_route *route)
{
	static char	 buf[1024];
	char		 tmp[32];
	const char	*sep = "";

	snprintf(buf, sizeof buf, "%s[", route->domain->name);

	if (route->port) {
		snprintf(tmp, sizeof tmp, "port=%i", (int)route->port);
		strlcat(buf, tmp, sizeof buf);
		sep = ",";
	}

	if (route->flags & ROUTE_STARTTLS) {
		strlcat(buf, sep, sizeof buf);
		sep = ",";
		strlcat(buf, "starttls", sizeof buf);
	}

	if (route->flags & ROUTE_SMTPS) {
		strlcat(buf, sep, sizeof buf);
		sep = ",";
		strlcat(buf, "smtps", sizeof buf);
	}

	if (route->flags & ROUTE_AUTH) {
		strlcat(buf, sep, sizeof buf);
		sep = ",";
		strlcat(buf, "auth=", sizeof buf);
		strlcat(buf, route->auth, sizeof buf);
	}

	if (route->cert) {
		strlcat(buf, sep, sizeof buf);
		sep = ",";
		strlcat(buf, "cert=", sizeof buf);
		strlcat(buf, route->cert, sizeof buf);
	}

	if (route->flags & ROUTE_MX) {
		strlcat(buf, sep, sizeof buf);
		sep = ",";
		strlcat(buf, "mx", sizeof buf);
	}

	if (route->flags & ROUTE_BACKUP) {
		strlcat(buf, sep, sizeof buf);
		strlcat(buf, "backup=", sizeof buf);
		strlcat(buf, route->backupname, sizeof buf);
	}

	strlcat(buf, "]", sizeof buf);

	return (buf);
}

static struct mta_route *
mta_route_for(struct envelope *e)
{
	struct ssl		 ssl;
	struct mta_route	 key, *route;

	bzero(&key, sizeof key);

	if (e->agent.mta.relay.flags & ROUTE_BACKUP) {
		key.domain = mta_domain(e->dest.domain, 0);
		key.backupname = e->agent.mta.relay.hostname;
	} else if (e->agent.mta.relay.hostname[0]) {
		key.domain = mta_domain(e->agent.mta.relay.hostname, 1);
		key.flags |= ROUTE_MX;
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

	if ((route = SPLAY_FIND(mta_route_tree, &routes, &key)) == NULL) {
		route = xcalloc(1, sizeof *route, "mta_route");
		TAILQ_INIT(&route->tasks);
		route->id = generate_uid();
		route->flags = key.flags;
		route->domain = key.domain;
		route->backupname = key.backupname ?
		    xstrdup(key.backupname, "mta: backupname") : NULL;
		route->backuppref = -1;
		route->port = key.port;
		route->cert = key.cert ? xstrdup(key.cert, "mta: cert") : NULL;
		route->auth = key.auth ? xstrdup(key.auth, "mta: auth") : NULL;
		if (route->cert) {
			strlcpy(ssl.ssl_name, route->cert,
			    sizeof(ssl.ssl_name));
			route->ssl = SPLAY_FIND(ssltree, env->sc_ssl, &ssl);
		}
		SPLAY_INSERT(mta_route_tree, &routes, route);

		route->maxconn = MTA_MAXCONN;
		route->maxmail = MTA_MAXMAIL;
		route->maxrcpt = MTA_MAXRCPT;

		route->maxsession = route->maxconn;

		log_trace(TRACE_MTA, "mta: new route %s",
		    mta_route_to_text(route));
		stat_increment("mta.route", 1);
		mta_route_query_mx(route);
		mta_route_query_secret(route);
	} else {
		mta_domain_unref(key.domain);
		log_trace(TRACE_MTA, "mta: reusing route %s",
		    mta_route_to_text(route));
	}

	return (route);
}

static void
mta_route_query_secret(struct mta_route *route)
{
	struct secret	secret;

	if (route->auth == NULL)
		return;

	tree_xset(&wait_secret, route->id, route);
	route->status |= ROUTE_WAIT_SECRET;

	bzero(&secret, sizeof(secret));
	secret.id = route->id;
	strlcpy(secret.tablename, route->auth, sizeof(secret.tablename));
	strlcpy(secret.host, route->domain->name, sizeof(secret.host));
	imsg_compose_event(env->sc_ievs[PROC_LKA], IMSG_LKA_SECRET,
		    0, 0, -1, &secret, sizeof(secret));
}

static void
mta_route_query_mx(struct mta_route *route)
{
	struct mta_mxlist *mxl;

	mxl = xcalloc(1, sizeof *mxl, "mta: mxlist");
	TAILQ_INIT(&mxl->mxs);
	mxl->route = route;
	tree_xset(&wait_mx, route->id, mxl);
	route->status |= ROUTE_WAIT_MX;

	if (route->flags & ROUTE_MX)
		dns_query_host(route->id, route->domain->name);
	else
		dns_query_mx(route->id, route->domain->name);

	if (route->backupname) {
		tree_xset(&wait_preference, route->id, route);
		route->status |= ROUTE_WAIT_PREFERENCE;
		dns_query_mx_preference(route->id, route->domain->name,
		    route->backupname);
	}
}



static void
mta_route_free(struct mta_route *route)
{
	struct mta_mx	*mx;

	log_debug("debug: mta: freeing route %s", mta_route_to_text(route));
	SPLAY_REMOVE(mta_route_tree, &routes, route);
	if (route->cert)
		free(route->cert);
	if (route->auth)
		free(route->auth);

	if (route->mxlist)
		while ((mx = TAILQ_FIRST(&route->mxlist->mxs))) {
			TAILQ_REMOVE(&route->mxlist->mxs, mx, entry);
			mta_host_unref(mx->host);
			free(mx);
		}
	mta_domain_unref(route->domain);
	free(route);
	stat_decrement("mta.route", 1);

}

static void
mta_route_flush(struct mta_route *route, int fail, const char *error)
{
	struct envelope	*e;
	struct mta_task	*task;
	const char	*pfx;
	char		 relay[MAX_LINE_SIZE];
	size_t		 n;

	if (fail == IMSG_QUEUE_DELIVERY_TEMPFAIL)
		pfx = "TempFail";
	else if (fail == IMSG_QUEUE_DELIVERY_PERMFAIL)
		pfx = "PermFail";
	else
		errx(1, "unexpected delivery status %i", fail);

	snprintf(relay, sizeof relay, "relay=%s, ", route->domain->name);

	n = 0;
	while ((task = TAILQ_FIRST(&route->tasks))) {
		TAILQ_REMOVE(&route->tasks, task, entry);
		while ((e = TAILQ_FIRST(&task->envelopes))) {
			TAILQ_REMOVE(&task->envelopes, e, entry);
			envelope_set_errormsg(e, "%s", error);
			log_envelope(e, relay, pfx, e->errorline);
			imsg_compose_event(env->sc_ievs[PROC_QUEUE], fail,
			    0, 0, -1, e, sizeof(*e));
			free(e);
			n++;
		}
		free(task);
	}

	stat_decrement("mta.task", route->ntask);
	stat_decrement("mta.envelope", n);
	route->ntask = 0;
}

static void
mta_route_drain(struct mta_route *route)
{
	char		 buf[64];

	log_debug("debug: mta: draining route %s "
	    "(tasks=%i, refs=%i, sessions=%i/%i)",
	    mta_route_to_text(route),
	    route->ntask, route->refcount, route->nsession, route->maxsession);

	/* Wait until we are ready to proceed */
	if (route->status & ROUTE_WAITMASK) {
		buf[0] = '\0';
		if (route->status & ROUTE_WAIT_MX)
			strlcat(buf, "MX ", sizeof buf);
		if (route->status & ROUTE_WAIT_PREFERENCE)
			strlcat(buf, "preference ", sizeof buf);
		if (route->status & ROUTE_WAIT_SECRET)
			strlcat(buf, "secret ", sizeof buf);
		log_debug("debug: mta: route %s waiting for %s",
		    mta_route_to_text(route), buf);
		return;
	}

	if (route->auth && route->secret == NULL) {
		log_warnx("warn: Failed to retreive secret for route %s",
		    mta_route_to_text(route));
		mta_route_flush(route, IMSG_QUEUE_DELIVERY_TEMPFAIL,
		    "Cannot retreive secret");
		if (route->refcount == 0)
			mta_route_free(route);
		return;
	}

	if (route->mxlist->error) {
		log_info("smtp-out: Failed to resolve MX for route %s: %s",
		    mta_route_to_text(route), route->mxlist->error);
		mta_route_flush(route, route->mxlist->errortype,
		    route->mxlist->error);
		if (route->refcount == 0)
			mta_route_free(route);
		return;
	}

	if (route->ntask == 0) {
		log_debug("debug: mta: all done for route %s",
		    mta_route_to_text(route));
		if (route->refcount == 0 && route->nsession == 0)
			mta_route_free(route);
		return;
	}

	if (route->status & ROUTE_CLOSED) {
		mta_route_flush(route, IMSG_QUEUE_DELIVERY_TEMPFAIL,
		    "No reachable MX");
		if (route->refcount == 0 && route->nsession == 0)
			mta_route_free(route);
		return;
	}

	/* Make sure there is one session for each task */
	while (route->nsession < route->ntask) {
		/*
		 * If we have reached the max number of session, just wait
		 */
		if (route->nsession >= route->maxsession) {
			log_debug("debug: mta: max conn reached for route %s",
			    mta_route_to_text(route));
			return;
		}
		route->nsession += 1;
		mta_session(route);
	}
}

static int
mta_route_cmp(const struct mta_route *a, const struct mta_route *b)
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

SPLAY_GENERATE(mta_route_tree, mta_route, entry, mta_route_cmp);

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
