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
#include <netdb.h>

#define	FILTER_API_VERSION	 50

#define MAX_LINE_SIZE		 2048
#define MAX_LOCALPART_SIZE	 64
#define MAX_DOMAINPART_SIZE	 255


SPLAY_HEAD(dict, dictentry);
SPLAY_HEAD(tree, treeentry);

enum filter_status {
	FILTER_OK,
	FILTER_PERMFAIL,
	FILTER_TEMPFAIL
};

/* XXX - server side requires mfa_session.c update on filter_hook changes */
enum filter_hook {
	HOOK_REGISTER		= 0,
	HOOK_CONNECT		= 0x001,
	HOOK_HELO		= 0x002,
	HOOK_EHLO		= 0x004,
	HOOK_MAIL		= 0x008,
	HOOK_RCPT		= 0x010,
	HOOK_DATALINE		= 0x020,
	HOOK_QUIT		= 0x040,
	HOOK_CLOSE		= 0x080,
	HOOK_RSET		= 0x100,
};

struct filter_connect {
	char			hostname[MAXHOSTNAMELEN];
	struct sockaddr_storage	hostaddr;
};

struct filter_helo {
	char			helohost[MAXHOSTNAMELEN];
};

struct filter_mail {
	char			user[MAX_LOCALPART_SIZE];
	char			domain[MAX_DOMAINPART_SIZE];
};

struct filter_rcpt {
	char			user[MAX_LOCALPART_SIZE];
	char			domain[MAX_DOMAINPART_SIZE];
};

struct filter_dataline {
	char			line[MAX_LINE_SIZE];
};

union filter_union {
	struct filter_connect	connect;
	struct filter_helo	helo;
	struct filter_mail	mail;
	struct filter_rcpt	rcpt;
	struct filter_dataline	dataline;
};

struct filter_msg {
	uint64_t		id;	 /* set by smtpd(8) */
	enum filter_status	status;
	uint32_t		code;
	char			errorline[MAX_LINE_SIZE];
	union filter_union	u;
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
void filter_api_init(void);
void filter_api_loop(void);
void filter_api_accept(uint64_t);
void filter_api_reject(uint64_t, enum filter_status);
void filter_api_reject_status(uint64_t, uint32_t, const char *);


void filter_api_register_connect_callback(void (*)(uint64_t, struct filter_connect *, void *), void *);
void filter_api_register_helo_callback(void (*)(uint64_t, struct filter_helo *, void *), void *);
void filter_api_register_ehlo_callback(void (*)(uint64_t, struct filter_helo *, void *), void *);
void filter_api_register_mail_callback(void (*)(uint64_t, struct filter_mail *, void *), void *);
void filter_api_register_rcpt_callback(void (*)(uint64_t, struct filter_rcpt *, void *), void *);
void filter_api_register_dataline_callback(void (*)(uint64_t, struct filter_dataline *, void *), void *);
void filter_api_register_quit_callback(void (*)(uint64_t, void *), void *);
void filter_api_register_close_callback(void (*)(uint64_t, void *), void *);
void filter_api_register_rset_callback(void (*)(uint64_t, void *), void *);


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
