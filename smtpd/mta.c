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

#define MAXERROR_PER_HOST	4

#define MAXCONN_PER_HOST	10
#define MAXCONN_PER_ROUTE	5
#define MAXCONN_PER_SOURCE	50
#define MAXCONN_PER_RELAY	100

static void mta_imsg(struct mproc *, struct imsg *);
static void mta_shutdown(void);
static void mta_sig_handler(int, short, void *);

static void mta_query_mx(struct mta_domain *);
static void mta_query_secret(struct mta_relay *);
static void mta_query_preference(struct mta_relay *);
static void mta_query_source(struct mta_relay *);
static void mta_on_mx(void *, void *, void *);
static void mta_on_source(struct mta_relay *, struct mta_source *);
static void mta_drain(struct mta_relay *);
static void mta_flush(struct mta_relay *, int, const char *);
static struct mta_route *mta_find_route(struct mta_relay*, struct mta_source*);

SPLAY_HEAD(mta_relay_tree, mta_relay);
static struct mta_relay *mta_relay(struct envelope *);
static void mta_relay_ref(struct mta_relay *);
static void mta_relay_unref(struct mta_relay *);
static int mta_relay_cmp(const struct mta_relay *, const struct mta_relay *);
SPLAY_PROTOTYPE(mta_relay_tree, mta_relay, entry, mta_relay_cmp);

SPLAY_HEAD(mta_host_tree, mta_host);
static struct mta_host *mta_host(const struct sockaddr *);
static void mta_host_ref(struct mta_host *);
static void mta_host_unref(struct mta_host *);
static int mta_host_cmp(const struct mta_host *, const struct mta_host *);
SPLAY_PROTOTYPE(mta_host_tree, mta_host, entry, mta_host_cmp);

SPLAY_HEAD(mta_domain_tree, mta_domain);
static struct mta_domain *mta_domain(char *, int);
static void mta_domain_ref(struct mta_domain *);
static void mta_domain_unref(struct mta_domain *);
static int mta_domain_cmp(const struct mta_domain *, const struct mta_domain *);
SPLAY_PROTOTYPE(mta_domain_tree, mta_domain, entry, mta_domain_cmp);

SPLAY_HEAD(mta_source_tree, mta_source);
static struct mta_source *mta_source(const struct sockaddr *);
static void mta_source_ref(struct mta_source *);
static void mta_source_unref(struct mta_source *);
static const char *mta_source_to_text(struct mta_source *);
static int mta_source_cmp(const struct mta_source *, const struct mta_source *);
SPLAY_PROTOTYPE(mta_source_tree, mta_source, entry, mta_source_cmp);

SPLAY_HEAD(mta_route_tree, mta_route);
static struct mta_route *mta_route(struct mta_source *, struct mta_host *);
static void mta_route_ref(struct mta_route *);
static void mta_route_unref(struct mta_route *);
static const char *mta_route_to_text(struct mta_route *);
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
static struct tree wait_source;

void
mta_imsg(struct mproc *p, struct imsg *imsg)
{
	struct lka_source_resp_msg	*resp_addr;
	struct dns_resp_msg	*resp_dns;
	struct mta_relay	*relay;
	struct mta_task		*task;
	struct mta_source	*source;
	struct mta_domain	*domain;
	struct mta_mx		*mx, *imx;
	struct sockaddr		*sa;
	struct tree		*batch;
	struct secret		*secret;
	struct envelope		*e;
	struct ssl		*ssl;
	uint64_t		 id;

	if (p->proc == PROC_QUEUE) {
		switch (imsg->hdr.type) {

		case IMSG_MTA_BATCH:
			id = *(uint64_t*)(imsg->data);
			batch = xmalloc(sizeof *batch, "mta_batch");
			tree_init(batch);
			tree_xset(&batches, id, batch);
			log_trace(TRACE_MTA,
			    "mta: batch:%016" PRIx64 " created", id);
			return;

		case IMSG_MTA_BATCH_ADD:
			e = xmemdup(imsg->data, sizeof *e, "mta:envelope");
			relay = mta_relay(e);
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
			} else
				mta_relay_unref(relay); /* from here */

			/*
			 * Technically, we could handle that by adding a msg
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

		case IMSG_MTA_BATCH_END:
			id = *(uint64_t*)(imsg->data);
			batch = tree_xpop(&batches, id);
			log_trace(TRACE_MTA, "mta: batch:%016" PRIx64 " closed",
			    id);
			/* For all tasks, queue them on its relay */
			while (tree_poproot(batch, &id, (void**)&task)) {
				if (id != task->relay->id)
					errx(1, "relay id mismatch!");
				relay = task->relay;
				relay->ntask += 1;
				TAILQ_INSERT_TAIL(&relay->tasks, task, entry);
				stat_increment("mta.task", 1);
				mta_drain(relay);
				mta_relay_unref(relay); /* from BATCH_APPEND */
			}
			free(batch);
			return;

		case IMSG_QUEUE_MESSAGE_FD:
			mta_session_imsg(p, imsg);
			return;
		}
	}

	if (p->proc == PROC_LKA) {
		switch (imsg->hdr.type) {

		case IMSG_LKA_SECRET:
			secret = imsg->data;
			relay = tree_xpop(&wait_secret, secret->id);
			if (secret->secret[0])
				relay->secret = strdup(secret->secret);
			if (relay->secret == NULL) {
				log_warnx("warn: Failed to retreive secret "
				    "for relay %s", mta_relay_to_text(relay));
				relay->fail = IMSG_DELIVERY_TEMPFAIL;
				relay->failstr = "Could not retreive secret";
			}
			relay->status &= ~RELAY_WAIT_SECRET;
			mta_drain(relay);
			mta_relay_unref(relay); /* from mta_query_secret() */
			return;

		case IMSG_LKA_SOURCE:
			resp_addr = imsg->data;
			relay = tree_xpop(&wait_source, resp_addr->reqid);
			relay->status &= ~RELAY_WAIT_SOURCE;
			if (resp_addr->status == LKA_OK) {
				sa = (struct sockaddr *)&resp_addr->ss;
				source = mta_source(sa);
				mta_on_source(relay, source);
			}
			else {
				log_warnx("warn: Failed to get source address"
				    "for relay %s", mta_relay_to_text(relay));
				relay->fail = IMSG_DELIVERY_TEMPFAIL;
				relay->failstr = "Could not get source address";
			}
			mta_drain(relay);
			mta_relay_unref(relay); /* from mta_query_source() */
			return;

		case IMSG_DNS_HOST:
			resp_dns = imsg->data;
			domain = tree_xget(&wait_mx, resp_dns->reqid);
			sa = (struct sockaddr*)&resp_dns->u.host.ss;
			mx = xcalloc(1, sizeof *mx, "mta: mx");
			mx->host = mta_host(sa);
			mx->preference = resp_dns->u.host.preference;
			TAILQ_FOREACH(imx, &domain->mxs, entry) {
				if (imx->preference >= mx->preference) {
					TAILQ_INSERT_BEFORE(imx, mx, entry);
					return;
				}
			}
			TAILQ_INSERT_TAIL(&domain->mxs, mx, entry);
			return;

		case IMSG_DNS_HOST_END:
			resp_dns = imsg->data;
			domain = tree_xpop(&wait_mx, resp_dns->reqid);
			domain->mxstatus = resp_dns->error;
			if (domain->mxstatus == DNS_OK) {
				log_debug("debug: MXs for domain %s:",
				    domain->name);
				TAILQ_FOREACH(mx, &domain->mxs, entry)
					log_debug("	%s preference %i",
					    sa_to_text(mx->host->sa),
					    mx->preference);
			}
			else {
				log_debug("debug: Failed MX query for %s:",
				    domain->name);
			}
			waitq_run(&domain->mxs, domain);
			return;

		case IMSG_DNS_MX_PREFERENCE:
			resp_dns = imsg->data;
			relay = tree_xpop(&wait_preference, resp_dns->reqid);
			if (resp_dns->error) {
				log_debug("debug: couldn't find backup "
				    "preference for relay %s",
				    mta_relay_to_text(relay));
				/* use all */
				relay->backuppref = INT_MAX;
			} else {
				relay->backuppref = resp_dns->u.preference;
				log_debug("debug: found backup preference %i "
				    "for relay %s",
				    relay->backuppref,
				    mta_relay_to_text(relay));
			}
			relay->status &= ~RELAY_WAIT_PREFERENCE;
			mta_drain(relay);
			mta_relay_unref(relay); /* from mta_query_preference() */
			return;

		case IMSG_DNS_PTR:
			mta_session_imsg(p, imsg);
			return;

		case IMSG_LKA_SSL_VERIFY:
			mta_session_imsg(p, imsg);
			return;
		}
	}

	if (p->proc == PROC_PARENT) {
		switch (imsg->hdr.type) {
		case IMSG_CONF_START:
			if (env->sc_flags & SMTPD_CONFIGURING)
				return;
			env->sc_flags |= SMTPD_CONFIGURING;
			env->sc_ssl_dict = xcalloc(1, sizeof *env->sc_ssl_dict,
			    "mta:sc_ssl_dict");
			return;

		case IMSG_CONF_SSL:
			if (!(env->sc_flags & SMTPD_CONFIGURING))
				return;
			ssl = xmemdup(imsg->data, sizeof *ssl, "mta:ssl");
			ssl->ssl_cert = xstrdup((char*)imsg->data + sizeof *ssl,
			    "mta:ssl_cert");
			ssl->ssl_key = xstrdup((char*)imsg->data +
			    sizeof *ssl + ssl->ssl_cert_len, "mta:ssl_key");
			dict_set(env->sc_ssl_dict, ssl->ssl_name, ssl);
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
	tree_init(&wait_source);

	imsg_callback = mta_imsg;
	event_init();

	signal_set(&ev_sigint, SIGINT, mta_sig_handler, NULL);
	signal_set(&ev_sigterm, SIGTERM, mta_sig_handler, NULL);
	signal_add(&ev_sigint, NULL);
	signal_add(&ev_sigterm, NULL);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	config_peer(PROC_PARENT);
	config_peer(PROC_QUEUE);
	config_peer(PROC_LKA);
	config_peer(PROC_CONTROL);
	config_done();

	if (event_dispatch() < 0)
		fatal("event_dispatch");
	mta_shutdown();

	return (0);
}

/*
 * Local error on the given source.
 */
void
mta_source_error(struct mta_relay *relay, struct mta_route *route, const char *e)
{
	log_info("smtp-out: Error on source %s: %s",
	    mta_source_to_text(route->src), e);

	/*
	 * Remember the source as broken for this relay.  Take a reference if
	 * it's not already marked by another session.
	 */
	if (tree_set(&relay->source_fail, ptoid(route->src), route->src) == NULL)
		mta_source_ref(route->src);
}

/*
 * TODO:
 * Currently all errors are reported on the host itself.  Technically,
 * it should depend on the error, and it would be probably better to report
 * it at the route level.  But we would need to have persistent routes
 * for that.  Hosts are "naturally" persisted, as they are referenced from
 * the MX list on the domain.
 */
void
mta_route_error(struct mta_relay *relay, struct mta_route *route, const char *e)
{
	log_info("smtp-out: Error on MX %s: %s",
	    mta_host_to_text(route->dst), e);

	if (++route->dst->nerror >= MAXERROR_PER_HOST) {
		route->dst->flags |= HOST_IGNORE;
		log_info("smtp-out: Too many errors on MX %s: ignoring this MX",
		    mta_host_to_text(route->dst));
	}
}

void
mta_route_ok(struct mta_relay *relay, struct mta_route *route)
{
	struct mta_source	*source;

	log_debug("debug: mta: route ok %s", mta_route_to_text(route));

	/*
	 * If a connection was successfully establish, reset all sources.
	 * This is suboptimal, but it avoids source loops. It must really
	 * be improved, but we need to have more specific error reports
	 * for that.
	 */
	while (tree_poproot(&relay->source_fail, NULL, (void**)&source))
		mta_source_unref(source); /* from mta_on_source() */

	route->dst->nerror = 0;
}

void
mta_route_collect(struct mta_relay *relay, struct mta_route *route)
{
	log_debug("debug: mta: route collect %s", mta_route_to_text(route));

	relay->nconn -= 1;
	route->nconn -= 1;
	route->src->nconn -= 1;
	route->dst->nconn -= 1;

	mta_route_unref(route); /* from mta_find_route() */

	/* Reset the limit */
	if (relay->limit_hit) {
		relay->limit_hit = 0;
		log_info("smtp-out: Resetting limit flag on relay %s",
		    mta_relay_to_text(relay));
	}
	mta_drain(relay);
	mta_relay_unref(relay); /* from mta_on_source */
}

struct mta_task *
mta_route_next_task(struct mta_relay *relay, struct mta_route *route)
{
	struct mta_task	*task;

	if ((task = TAILQ_FIRST(&relay->tasks))) {
		TAILQ_REMOVE(&relay->tasks, task, entry);
		relay->ntask -= 1;
		task->relay = NULL;
	}

	return (task);
}

static void
mta_query_mx(struct mta_domain *domain)
{
	uint64_t	id;

	log_debug("debug: mta_query_mx(%s)", domain->name);

	id = generate_uid();
	tree_xset(&wait_mx, id, domain);
	if (domain->flags)
		dns_query_host(id, domain->name);
	else
		dns_query_mx(id, domain->name);
	domain->lastmxquery = time(NULL);
}

static void
mta_query_secret(struct mta_relay *relay)
{
	struct secret	secret;

	log_debug("debug: mta_query_secret(%s)", mta_relay_to_text(relay));

	tree_xset(&wait_secret, relay->id, relay);
	relay->status |= RELAY_WAIT_SECRET;

	bzero(&secret, sizeof(secret));
	secret.id = relay->id;
	strlcpy(secret.tablename, relay->authtable, sizeof(secret.tablename));
	strlcpy(secret.label, relay->authlabel, sizeof(secret.label));
	m_compose(p_lka, IMSG_LKA_SECRET, 0, 0, -1, &secret, sizeof(secret));
	mta_relay_ref(relay);
}

static void
mta_query_preference(struct mta_relay *relay)
{

	log_debug("debug: mta_query_preference(%s)", mta_relay_to_text(relay));

	tree_xset(&wait_preference, relay->id, relay);
	relay->status |= RELAY_WAIT_PREFERENCE;
	dns_query_mx_preference(relay->id, relay->domain->name,
		relay->backupname);
	mta_relay_ref(relay);
}

static void
mta_query_source(struct mta_relay *relay)
{
	struct lka_source_req_msg	req;

	log_debug("debug: mta_query_source(%s)", mta_relay_to_text(relay));

	req.reqid = relay->id;
	strlcpy(req.tablename, relay->sourcetable, sizeof(req.tablename));
	m_compose(p_lka, IMSG_LKA_SOURCE, 0, 0, -1, &req, sizeof(req));
	tree_xset(&wait_source, relay->id, relay);
	relay->status |= RELAY_WAIT_SOURCE;
	mta_relay_ref(relay);
}

static void
mta_on_mx(void *tag, void *arg, void *data)
{
	struct mta_domain	*domain = data;
	struct mta_relay	*relay = arg;

	log_debug("debug: mta_on_mx(%p, %s, %s)",
	    tag, domain->name, mta_relay_to_text(relay));

	switch (domain->mxstatus) {
	case DNS_OK:
		break;
	case DNS_RETRY:
		relay->fail = IMSG_DELIVERY_TEMPFAIL;
		relay->failstr = "Temporary failure in MX lookup";
		break;
	case DNS_EINVAL:
		relay->fail = IMSG_DELIVERY_PERMFAIL;
		relay->failstr = "Invalid domain name";
		break;
	case DNS_ENONAME:
		relay->fail = IMSG_DELIVERY_PERMFAIL;
		relay->failstr = "Domain does not exist";
		break;
	case DNS_ENOTFOUND:
		relay->fail = IMSG_DELIVERY_TEMPFAIL;
		relay->failstr = "No MX found for domain";
		break;
	default:
		fatalx("bad DNS lookup error code");
		break;
	}

	if (domain->mxstatus)
		log_info("smtp-out: Failed to resolve MX for relay %s: %s",
		    mta_relay_to_text(relay), relay->failstr);

	relay->status &= ~RELAY_WAIT_MX;
	mta_drain(relay);
	mta_relay_unref(relay); /* from mta_drain() */
}

static void
mta_on_source(struct mta_relay *relay, struct mta_source *source)
{
	struct mta_route	*route;
	uint64_t		 id;

	log_debug("debug: mta_on_source(%s, %s)",
	    mta_relay_to_text(relay), mta_source_to_text(source));

	/* Give up right away if the relay is already failing */
	if (relay->fail) {
		log_debug("debug: mta: relay is failing, giving up");
		mta_source_unref(source); /* from IMSG_LKA_SOURCE */
		return;
	}

	id = ptoid(source);
	if (tree_check(&relay->source_fail, id)) {
		/*
		 * If this source has been tried already, and there is no
		 * active connection (which would mean that a source was found
		 * to be useable), assume we looped over all available source
		 * addresses, and all of them failed.
		 */
		log_debug("debug: mta: source already tried");
		if (relay->nconn == 0) {
			relay->fail = IMSG_DELIVERY_TEMPFAIL;
			relay->failstr = "Could not find a valid source address";
		}
		mta_source_unref(source); /* from IMSG_LKA_SOURCE */
		return;
	}

	route = mta_find_route(relay, source);
	if (route) {
		mta_source_unref(source); /* transfered to mta_route() */
		mta_relay_ref(relay);
		relay->nconn += 1;
		relay->lastconn = time(NULL);
		route->nconn += 1;
		route->lastconn = relay->lastconn;
		route->src->nconn += 1;
		route->src->lastconn = relay->lastconn;
		route->dst->nconn += 1;
		route->dst->lastconn = relay->lastconn;
		mta_session(relay, route);
		return;
	}
	else {
		mta_source_unref(source); /* from IMSG_LKA_SOURCE */
	}
}

static void
mta_drain(struct mta_relay *r)
{
	char buf[64];

	log_debug("debug: mta: draining relay %s "
	    "(refcount=%i, ntask=%zu, nconn=%zu)", 
	    mta_relay_to_text(r), r->refcount, r->ntask, r->nconn);

	mta_relay_ref(r);

	/*
	 * If we know that this relay is failing and there are no session
	 * currently running, flush the tasks.
	 */
	if (r->fail && r->nconn == 0) {
		mta_flush(r, r->fail, r->failstr);
		goto done;
	}

	/* Query secret if needed */
	if (r->flags & RELAY_AUTH && r->secret == NULL &&
	    !(r->status & RELAY_WAIT_SECRET))
		mta_query_secret(r);

	/* Query our preference if needed */
	if (r->backupname && r->backuppref == -1 && !(r->status & RELAY_WAIT_PREFERENCE))
		mta_query_preference(r);

	/* Query the domain MXs if needed */
	if (r->domain->lastmxquery == 0 && !(r->status & RELAY_WAIT_MX)) {
		if (waitq_wait(&r->domain->mxs, mta_on_mx, r))
			mta_query_mx(r->domain);
		r->status |= RELAY_WAIT_MX;
		mta_relay_ref(r);
	}

	/* Wait until we are ready to proceed */
	if (r->status & RELAY_WAITMASK) {
		buf[0] = '\0';
		if (r->status & RELAY_WAIT_MX)
			strlcat(buf, "MX ", sizeof buf);
		if (r->status & RELAY_WAIT_PREFERENCE)
			strlcat(buf, "preference ", sizeof buf);
		if (r->status & RELAY_WAIT_SECRET)
			strlcat(buf, "secret ", sizeof buf);
		if (r->status & RELAY_WAIT_SOURCE)
			strlcat(buf, "source ", sizeof buf);
		log_debug("debug: mta: relay %s waiting for %s",
		    mta_relay_to_text(r), buf);
		goto done;
	}

	if (r->ntask == 0) {
		log_debug("debug: mta: all done for relay %s",
		    mta_relay_to_text(r));
		goto done;
	}

	/*
	 * Relay is failing, but there are sessions running
	 */
	if (r->fail) {
		log_debug("debug: mta: relay %s is failing, but has sessions",
		    mta_relay_to_text(r));
		goto done;
	}

	/*
	 * Create new sessions if possible/necessary.
	 */
	while (r->nconn < r->ntask && r->fail == 0 && !r->limit_hit) {

		if (r->nconn >= MAXCONN_PER_RELAY) {
			log_info("smtp-out: Hit connection limit on relay %s",
			    mta_relay_to_text(r));
			r->limit_hit = 1;
			goto done;
		}

		if (r->sourcetable) {
			mta_query_source(r);
			goto done;
		}
		else
			mta_on_source(r, mta_source(NULL));
	}

	if (r->nconn == 0 && r->ntask && r->fail)
		mta_drain(r);

    done:
	mta_relay_unref(r); /* from here */
}

static void
mta_flush(struct mta_relay *relay, int fail, const char *error)
{
	struct envelope	*e;
	struct mta_task	*task;
	const char	*pfx;
	char		 buf[MAX_LINE_SIZE];
	size_t		 n;

	log_debug("debug: mta_flush(%s, %i, \"%s\")",
	    mta_relay_to_text(relay), fail, error);

	if (fail == IMSG_DELIVERY_TEMPFAIL)
		pfx = "TempFail";
	else if (fail == IMSG_DELIVERY_PERMFAIL)
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
			m_compose(p_queue, fail, 0, 0, -1, e, sizeof(*e));
			free(e);
			n++;
		}
		free(task);
	}

	stat_decrement("mta.task", relay->ntask);
	stat_decrement("mta.envelope", n);
	relay->ntask = 0;
}

/*
 * Find a route to use for this relay with the given source.
 */
static struct mta_route *
mta_find_route(struct mta_relay *relay, struct mta_source *source)
{
	struct mta_route	*route, *best;
	struct mta_mx		*mx;
	int			 level, limit_host, limit_route;
	int			 family_mismatch, seen;

	limit_host = 0;
	limit_route = 0;
	family_mismatch = 0;
	level = -1;
	best = NULL;
	seen = 0;

	TAILQ_FOREACH(mx, &relay->domain->mxs, entry) {
		/*
		 * New preference level
		 */		
		if (mx->preference > level) {
#ifndef IGNORE_MX_PREFERENCE
			/*
			 * Use the current best MX if found.
			 */
			if (best)
				break;

			/*
			 * No candidate found.  There are valid MXs at this
			 * preference level but they reached their limit.
			 */
			if (limit_host || limit_route)
				break;

			/*
			 *  If we are a backup MX, do not relay to MXs with
			 *  a greater preference value.
			 */
			if (relay->backuppref >= 0 &&
			    mx->preference >= relay->backuppref)
				break;

			/*
			 * Start looking at MXs on this preference level.
			 */ 
#endif
			level = mx->preference;
		}

		if (mx->host->flags & HOST_IGNORE)
			continue;

		/* Found a possibly valid mx */
		seen++;

		if (mx->host->nconn >= MAXCONN_PER_HOST) {
			limit_host = 1;
			continue;
		}

		if (source->sa &&
		    source->sa->sa_family != mx->host->sa->sa_family) {
			family_mismatch = 1;
			continue;
		}

		route = mta_route(source, mx->host);

		if (route->nconn >= MAXCONN_PER_ROUTE) {
			limit_route = 1;
			mta_route_unref(route); /* from here */
			continue;
		}

		/* Use the route with the lowest number of connections. */
		if (best && route->nconn >= best->nconn) {
			mta_route_unref(route); /* from here */
			continue;
		}

		if (best)
			mta_route_unref(best); /* from here */
		best = route;
	}

	if (best)
		return (best);

	if (family_mismatch) {
		log_debug("debug: mta: Address family mismatch for relay %s",
		    mta_relay_to_text(relay));

		/* Remember that this route is not useable */
		mta_source_ref(source);
		tree_xset(&relay->source_fail, ptoid(source), source);
		return (NULL);
	}

	/*
	 * XXX this is not really correct, since we could be hitting a limit
	 * because of another relay, and we might never have a chance to
	 * reset the limit. What we should is put ourself on a waitq for
	 * that resource and reset+drain when that resource is possibly
	 * available.
	 */
	if (limit_host) {
		log_info("smtp-out: Hit host limit on relay %s",
		    mta_relay_to_text(relay));
		relay->limit_hit = 1;
	}
	if (limit_route) {
		log_info("smtp-out: Hit route limit on relay %s",
		    mta_relay_to_text(relay));
		relay->limit_hit = 1;
	}
	/*
	 * No reachable MX for this relay with this source.
	 * XXX Not until we tried all possible sources, and this might 
	 * change when limits are reset.
	 */
	if (relay->nconn == 0 || seen == 0) {
		log_info("smtp-out: No reachable MX for relay %s",
		    mta_relay_to_text(relay));
		relay->fail = IMSG_DELIVERY_TEMPFAIL;
		relay->failstr = "No MX could be reached";
	}

	return (NULL);
}

static struct mta_relay *
mta_relay(struct envelope *e)
{
	struct mta_relay	 key, *r;

	bzero(&key, sizeof key);

	if (e->agent.mta.relay.flags & RELAY_BACKUP) {
		key.domain = mta_domain(e->dest.domain, 0);
		key.backupname = e->agent.mta.relay.hostname;
	} else if (e->agent.mta.relay.hostname[0]) {
		key.domain = mta_domain(e->agent.mta.relay.hostname, 1);
		key.flags |= RELAY_MX;
	} else {
		key.domain = mta_domain(e->dest.domain, 0);
	}

	key.flags = e->agent.mta.relay.flags;
	key.port = e->agent.mta.relay.port;
	key.cert = e->agent.mta.relay.cert;
	if (!key.cert[0])
		key.cert = NULL;
	key.authtable = e->agent.mta.relay.authtable;
	if (!key.authtable[0])
		key.authtable = NULL;
	key.authlabel = e->agent.mta.relay.authlabel;
	if (!key.authlabel[0])
		key.authlabel = NULL;
	key.sourcetable = e->agent.mta.relay.sourcetable;
	if (!key.sourcetable[0])
		key.sourcetable = NULL;

	if ((r = SPLAY_FIND(mta_relay_tree, &relays, &key)) == NULL) {
		r = xcalloc(1, sizeof *r, "mta_relay");
		TAILQ_INIT(&r->tasks);
		tree_init(&r->source_fail);
		r->id = generate_uid();
		r->flags = key.flags;
		r->domain = key.domain;
		r->backupname = key.backupname ?
		    xstrdup(key.backupname, "mta: backupname") : NULL;
		r->backuppref = -1;
		r->port = key.port;
		r->cert = key.cert ? xstrdup(key.cert, "mta: cert") : NULL;
		if (key.authtable)
			r->authtable = xstrdup(key.authtable, "mta: authtable");
		if (key.authlabel)
			r->authlabel = xstrdup(key.authlabel, "mta: authlabel");
		if (r->cert) {
			r->ssl = dict_get(env->sc_ssl_dict, r->cert);
		}
		if (key.sourcetable)
			r->sourcetable = xstrdup(key.sourcetable,
			    "mta: sourcetable");
		SPLAY_INSERT(mta_relay_tree, &relays, r);
		log_trace(TRACE_MTA, "mta: new relay %s", mta_relay_to_text(r));
		stat_increment("mta.relay", 1);
	} else {
		mta_domain_unref(key.domain); /* from here */
		log_trace(TRACE_MTA, "mta: reusing relay %s",
		    mta_relay_to_text(r));
	}

	r->refcount++;
	return (r);
}

static void
mta_relay_ref(struct mta_relay *r)
{
	r->refcount++;
}

static void
mta_relay_unref(struct mta_relay *relay)
{
	struct mta_source	*source;

	if (--relay->refcount)
		return;

	log_debug("debug: mta: freeing relay %s", mta_relay_to_text(relay));
	SPLAY_REMOVE(mta_relay_tree, &relays, relay);
	if (relay->cert)
		free(relay->cert);
	if (relay->authtable)
		free(relay->authtable);
	if (relay->authlabel)
		free(relay->authlabel);

	while (tree_poproot(&relay->source_fail, NULL, (void**)&source))
		mta_source_unref(source); /* from mta_on_source() */

	mta_domain_unref(relay->domain); /* from constructor */
	free(relay);
	stat_decrement("mta.relay", 1);
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
		strlcat(buf, relay->authtable, sizeof buf);
		strlcat(buf, ":", sizeof buf);
		strlcat(buf, relay->authlabel, sizeof buf);
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

	if (relay->sourcetable) {
		strlcat(buf, sep, sizeof buf);
		strlcat(buf, "sourcetable=", sizeof buf);
		strlcat(buf, relay->sourcetable, sizeof buf);
	}

	strlcat(buf, "]", sizeof buf);

	return (buf);
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

	if (a->authtable == NULL && b->authtable)
		return (-1);
	if (a->authtable && b->authtable == NULL)
		return (1);
	if (a->authtable && ((r = strcmp(a->authtable, b->authtable))))
		return (r);
	if (a->authlabel && ((r = strcmp(a->authlabel, b->authlabel))))
		return (r);
	if (a->sourcetable == NULL && b->sourcetable)
		return (-1);
	if (a->sourcetable && b->sourcetable == NULL)
		return (1);
	if (a->sourcetable && ((r = strcmp(a->sourcetable, b->sourcetable))))
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
mta_host_ref(struct mta_host *h)
{
	h->refcount++;
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

const char *
mta_host_to_text(struct mta_host *h)
{
	static char buf[1024];

	if (h->ptrname)
		snprintf(buf, sizeof buf, "%s [%s]",
		    h->ptrname, sa_to_text(h->sa));
	else
		snprintf(buf, sizeof buf, "[%s]", sa_to_text(h->sa));

	return (buf);
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
mta_domain_ref(struct mta_domain *d)
{
	d->refcount++;
}

static void
mta_domain_unref(struct mta_domain *d)
{
	struct mta_mx	*mx;

	if (--d->refcount)
		return;

	while ((mx = TAILQ_FIRST(&d->mxs))) {
		TAILQ_REMOVE(&d->mxs, mx, entry);
		mta_host_unref(mx->host); /* from IMSG_DNS_HOST */
		free(mx);
	}

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
mta_source_ref(struct mta_source *s)
{
	s->refcount++;
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

static const char *
mta_source_to_text(struct mta_source *s)
{
	static char buf[1024];

	if (s->sa == NULL)
		return "[]";
	snprintf(buf, sizeof buf, "[%s]", sa_to_text(s->sa));
	return (buf);
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
		mta_source_ref(src);
		mta_host_ref(dst);
		stat_increment("mta.route", 1);
	}

	r->refcount++;
	return (r);
}

static void
mta_route_ref(struct mta_route *r)
{
	r->refcount++;
}

static void
mta_route_unref(struct mta_route *r)
{
	if (--r->refcount)
		return;

	SPLAY_REMOVE(mta_route_tree, &routes, r);
	mta_source_unref(r->src); /* from constructor */
	mta_host_unref(r->dst); /* from constructor */
	stat_decrement("mta.route", 1);
}

static const char *
mta_route_to_text(struct mta_route *r)
{
	static char	buf[1024];

	snprintf(buf, sizeof buf, "%s <--> %s",
	    mta_source_to_text(r->src),
	    mta_host_to_text(r->dst));

	return (buf);
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
