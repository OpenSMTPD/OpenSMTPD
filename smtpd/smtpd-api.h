/*	$OpenBSD: filter_api.h,v 1.4 2012/08/20 21:14:17 gilles Exp $	*/

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

#ifndef	_SMTPD_API_H_
#define	_SMTPD_API_H_

#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netdb.h>

#define	FILTER_API_VERSION	 50

#define MAX_LINE_SIZE		 2048
#define MAX_LOCALPART_SIZE	 64
#define MAX_DOMAINPART_SIZE	 255

SPLAY_HEAD(dict, dictentry);
SPLAY_HEAD(tree, treeentry);

enum filter_status {
	FILTER_OK,
	FILTER_FAIL,
	FILTER_CLOSE,
};

enum filter_imsg {
	IMSG_FILTER_REGISTER,
	IMSG_FILTER_EVENT,
	IMSG_FILTER_QUERY,
	IMSG_FILTER_NOTIFY,
	IMSG_FILTER_DATA,
	IMSG_FILTER_RESPONSE,
};

#define	FILTER_ALTERDATA	0x01 /* The filter wants to alter the message */

/* XXX - server side requires mfa_session.c update on filter_hook changes */
enum filter_hook {
	HOOK_CONNECT		= 1 << 0,	/* req */
	HOOK_HELO		= 1 << 1,	/* req */
	HOOK_MAIL		= 1 << 2,	/* req */
	HOOK_RCPT		= 1 << 3,	/* req */
	HOOK_DATA		= 1 << 4,	/* req */
	HOOK_ENDOFDATA		= 1 << 5,	/* req */

	HOOK_RESET		= 1 << 6,	/* evt */
	HOOK_DISCONNECT		= 1 << 7,	/* evt */
	HOOK_COMMIT		= 1 << 8,	/* evt */
	HOOK_ROLLBACK		= 1 << 9,	/* evt */

	HOOK_DATALINE		= 1 << 10,	/* data */
};

struct filter_connect {
	struct sockaddr_storage	local;
	struct sockaddr_storage	remote;
	char			hostname[MAXHOSTNAMELEN];
};

struct filter_line {
	char			line[MAX_LINE_SIZE];
};

struct filter_mailaddr {
	char			user[MAX_LOCALPART_SIZE];
	char			domain[MAX_DOMAINPART_SIZE];
};

struct filter_register_msg {
	int	hooks;
	int	flags;
};

struct filter_query_msg {
	uint64_t			id;
	uint64_t			qid;
	enum filter_hook		hook;
	union {
		struct filter_connect	connect;
		struct filter_line	line;
		struct filter_mailaddr	maddr;
	} u;
};

struct filter_event_msg {
	uint64_t		id;
	enum filter_hook	event;
};

struct filter_notify_msg {
	uint64_t		qid;
	enum filter_status	status;
};

struct filter_data_msg {
	uint64_t		id;
	char			line[MAX_LINE_SIZE];
};

struct filter_response_msg {
	uint64_t		qid;
	enum filter_status	status;
	uint32_t		code;
	int			notify;
	char			response[MAX_LINE_SIZE];
};

/* dict.c */
#define dict_init(d) SPLAY_INIT((d))
#define dict_empty(d) SPLAY_EMPTY((d))
int dict_check(struct dict *, const char *);
void *dict_set(struct dict *, const char *, void *);
void dict_xset(struct dict *, const char *, void *);
void *dict_get(struct dict *, const char *);
void *dict_xget(struct dict *, const char *);
void *dict_pop(struct dict *, const char *);
void *dict_xpop(struct dict *, const char *);
int dict_poproot(struct dict *, const char * *, void **);
int dict_root(struct dict *, const char * *, void **);
int dict_iter(struct dict *, void **, const char * *, void **);
int dict_iterfrom(struct dict *, void **, const char *, const char **, void **);
void dict_merge(struct dict *, struct dict *);

/* filter_api.c */
void filter_api_loop(void);
void filter_api_accept(uint64_t);
void filter_api_accept_notify(uint64_t);
void filter_api_reject(uint64_t, enum filter_status);
void filter_api_reject_code(uint64_t, enum filter_status, uint32_t,
    const char *);
void filter_api_data(uint64_t, const char *);

/* tree.c */
#define tree_init(t) SPLAY_INIT((t))
#define tree_empty(t) SPLAY_EMPTY((t))
int tree_check(struct tree *, uint64_t);
void *tree_set(struct tree *, uint64_t, void *);
void tree_xset(struct tree *, uint64_t, void *);
void *tree_get(struct tree *, uint64_t);
void *tree_xget(struct tree *, uint64_t);
void *tree_pop(struct tree *, uint64_t);
void *tree_xpop(struct tree *, uint64_t);
int tree_poproot(struct tree *, uint64_t *, void **);
int tree_root(struct tree *, uint64_t *, void **);
int tree_iter(struct tree *, void **, uint64_t *, void **);
int tree_iterfrom(struct tree *, void **, uint64_t, uint64_t *, void **);
void tree_merge(struct tree *, struct tree *);

#endif
