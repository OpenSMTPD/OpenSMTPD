/*
 * Copyright (c) 2010 Gilles Chehade <gilles@openbsd.org>
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

#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <imsg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "smtpd.h"
#include "aldap.h"
#include "log.h"

#define MAX_LDAP_IDENTIFIER		 32
#define MAX_LDAP_URL		 	 256
#define MAX_LDAP_USERNAME      	 256
#define MAX_LDAP_PASSWORD      	 256
#define MAX_LDAP_BASELEN      	 128
#define MAX_LDAP_FILTERLEN     	 1024
#define MAX_LDAP_FIELDLEN      	 128

static void			*table_ldap_open(struct table *);
static int			 table_ldap_update(struct table *);
static int			 table_ldap_config(struct table *, const char *);
static int			 table_ldap_lookup(void *, const  char *, enum table_service, void **);
static void			 table_ldap_close(void *);
static char					*table_ldap_expandfilter(const char*, const char *);
static struct aldap			*ldap_client_connect(const char *);

struct table_backend table_backend_ldap = {
	K_ALIAS,
	table_ldap_config,
	table_ldap_open,
	table_ldap_update,
	table_ldap_close,
	table_ldap_lookup
};

struct ldaphandle {
	struct aldap	 *aldap;
	struct table	 *table;
};

static int			 table_ldap_alias(struct ldaphandle *, const char *, void**);
/*static int			 table_ldap_virtual(void *, const char *, void **);*/


static int
table_ldap_config(struct table *table, const char *config)
{
	struct table	*cfg;

	/* no config ? broken */
	if (config == NULL)
		return 0;

	cfg = table_create("static", NULL, NULL);

	if (! table_config_parser(cfg, config))
		goto err;

	if (cfg->t_type != T_HASH)
		goto err;

	/* sanity checks */
	if (table_get(cfg, "url") == NULL) {
		log_warnx("table_ldap: missing 'url' configuration");
		table_destroy(cfg);
		return 0;
	}

	table_set_config(table, cfg);
	return 1;

err:
	table_destroy(cfg);
	return 0;
}

static int
table_ldap_update(struct table *table)
{
	return 1;
}

static void *
table_ldap_open(struct table *table)
{
	struct table		 *cfg;
	struct ldaphandle	 *ldaphandle;
	struct aldap_message *message = NULL;


	ldaphandle = calloc(1, sizeof(*ldaphandle));
	if (ldaphandle == NULL)
		err(1, "calloc");

	cfg = table_get_config(table);

	ldaphandle->table = table;
	ldaphandle->aldap = ldap_client_connect(table_get(cfg, "url"));
	if (ldaphandle->aldap == NULL) {
		log_warnx("table_ldap_open: ldap_client_connect error");
		goto err;
	}

	if (aldap_bind(ldaphandle->aldap, table_get(cfg, "username")
				, table_get(cfg, "password")) == -1) {
		log_warnx("table_ldap_open: aldap_bind error");
		goto err;
	}

	if ((message = aldap_parse(ldaphandle->aldap)) == NULL) {
		log_warnx("table_ldap_open: aldap_parse");
		goto err;
	}

	switch (aldap_get_resultcode(message)) {
	case LDAP_SUCCESS:
		log_warnx("table_ldap_open: ldap server accepted credentials");
		break;
	case LDAP_INVALID_CREDENTIALS:
		log_warnx("table_ldap_open: ldap server refused credentials");
		goto err;

	default:
		log_warnx("table_ldap_open: failed to bind, result #%d", aldap_get_resultcode(message));
		goto err;
	}

	return ldaphandle;

err:
	if (ldaphandle->aldap != NULL)
		aldap_close(ldaphandle->aldap);
	free(ldaphandle);
	if (message != NULL)
		aldap_freemsg(message);
	return NULL;
}

static void
table_ldap_close(void *hdl)
{
	struct ldaphandle *ldaphandle = hdl;

	aldap_close(ldaphandle->aldap);
	free(ldaphandle);
}

static int
table_ldap_lookup(void *hdl, const char *key, enum table_service service,
		void **retp)
{
	int ret = 0;
	struct ldaphandle *ldap_handle = hdl;

	switch (service) {
	case K_ALIAS:
		ret = table_ldap_alias(ldap_handle, key, retp);
		break;
	default:
		break;
	}

	return ret;
}

static int
table_ldap_alias(struct ldaphandle *hdl, const char *key, void **retp)
{
	struct aldap *aldap = hdl->aldap;
	struct table *cfg = table_get_config(hdl->table);
	const char   *filter = NULL;
	const char	 *basedn = NULL;
	struct aldap_page_control *pg = NULL;
	struct aldap_message *m = NULL;
	struct expand		  *expand = NULL;
	struct expandnode	  expnode;
	char *expandedfilter = NULL;
	char *attributes[2];
	char **ldapattrsp = NULL;
	int i, ret;


	if ((filter = table_get(cfg, "alias_filter")) == NULL) {
		log_warnx("table_ldap: lookup: no filter configured for aliases");
		return -1;
	}

	if ((expandedfilter = table_ldap_expandfilter(filter, key)) == NULL) {
		log_warnx("table_ldap: lookup: couldn't expand filter");
		return -1;
	}

	if ((basedn = table_get(cfg, "basedn")) == NULL) {
		log_warnx("table_ldap: lookup: no base dn configured");
		return -1;
	}

	if ((attributes[0] = table_get(cfg, "alias_attribute")) == NULL) {
		log_warnx("table_ldap: lookup: no attribute configured for aliases");
		return -1;
	}
	attributes[1] = NULL;

	if ((expand = calloc(1, sizeof(struct expand))) == NULL)
			err(1, NULL);

	do {
		ret = aldap_search(aldap, basedn, LDAP_SCOPE_SUBTREE, expandedfilter,
				attributes, 0, 0, 0, pg);

		if (ret == -1)
			goto error;

		if (pg != NULL) {
			aldap_freepage(pg);
			pg = NULL;
		}

		while ((m = aldap_parse(aldap)) != NULL) {
			if (aldap->msgid != m->msgid)
				goto error;

			if (m->message_type == LDAP_RES_SEARCH_RESULT) {
				if (m->page != NULL && m->page->cookie_len != 0)
					pg = m->page;
				else
					pg = NULL;

				aldap_freemsg(m);
				break;
			}

			if (m->message_type != LDAP_RES_SEARCH_ENTRY)
				goto error;

			if (aldap_match_attr(m, attributes[0], &ldapattrsp) != 1)
				goto error;

			for (i = 0; ldapattrsp[i]; ++i) {
				if (!alias_parse(&expnode, ldapattrsp[i]))
					goto error;

				expand_insert(expand, &expnode);
			}

			aldap_freemsg(m);
		}
	} while (pg != NULL);

	aldap_free_attr(ldapattrsp);
	free(expandedfilter);
	*retp = expand;
	return 1;

error:
	free(expandedfilter);
	expand_free(expand);
	free(expand);
	*retp = NULL;
	aldap_freemsg(m);
	if (pg != NULL)
		aldap_freepage(pg);

	return -1;
}

#if 0
static int
table_ldap_virtual(void *hdl, const char *key, void **retp)
{
	struct ldaphandle *ldaphandle = hdl;
	struct aldap *aldap = ldaphandle->aldap;
	struct aldap_page_control *pg = NULL;
	struct aldap_message *m = NULL;
	struct table_virtual	 *table_virtual = NULL;
	struct expandnode	  expnode;
	char *expandedfilter = NULL;
	char *attributes[2];
	char **ldapattrsp = NULL;
	int i, ret;


	if ((expandedfilter = table_ldap_expandfilter(ldaphandle, key)) == NULL)
		return -1;

	attributes[0] = ldaphandle->conf->m_ldapattr;
	attributes[1] = NULL;

	/* domain key, discard value */
	if (strchr(key, '@') == NULL) {
		*retp = NULL;
		return 1;
	}

	if ((table_virtual = calloc(1, sizeof(struct table_virtual))) == NULL)
			err(1, NULL);

	do {
		ret = aldap_search(aldap, ldaphandle->conf->m_ldapbasedn, LDAP_SCOPE_SUBTREE,
				expandedfilter, attributes, 0, 0, 0, pg);

		if (ret == -1) {
			free(table_virtual);
			return -1;
		}

		if (pg != NULL) {
			aldap_freepage(pg);
			pg = NULL;
		}

		while ((m = aldap_parse(aldap)) != NULL) {
			if (aldap->msgid != m->msgid)
				goto error;

			if (m->message_type == LDAP_RES_SEARCH_RESULT) {
				if (m->page != NULL && m->page->cookie_len != 0)
					pg = m->page;
				else
					pg = NULL;

				aldap_freemsg(m);
				break;
			}

			if (m->message_type != LDAP_RES_SEARCH_ENTRY)
				goto error;

			if (aldap_match_attr(m, attributes[0], &ldapattrsp) != 1)
				goto error;

			for (i = 0; ldapattrsp[i]; ++i) {
				bzero(&expnode, sizeof(struct expandnode));
				if (!alias_parse(&expnode, ldapattrsp[i]))
					goto error;

				expand_insert(&table_virtual->expand, &expnode);
				table_virtual->nbnodes++;
			}

			aldap_freemsg(m);
		}
	} while (pg != NULL);


	aldap_free_attr(ldapattrsp);
	free(expandedfilter);
	*retp = table_virtual;
	return 1;

error:
	expand_free(&table_virtual->expand);
	free(expandedfilter);
	free(table_virtual);
	aldap_freemsg(m);
	if (pg != NULL)
		aldap_freepage(pg);

	return -1;
}
#endif 

static char	*
table_ldap_expandfilter(const char *filter, const char *key)
{
	char expandedfilter[MAX_LDAP_FILTERLEN * 2];
	size_t i, j;

	bzero(expandedfilter, sizeof(expandedfilter));
	for (i = 0, j = 0; filter[i] != '\0'; ++i, ++j) {
		if (j >= sizeof(expandedfilter))
			return NULL;

		if (filter[i] == '%') {
			if (filter[i + 1] == 'k') {
				if (strlcat(expandedfilter, key, sizeof(expandedfilter))
						>= sizeof(expandedfilter))
					return NULL;

				j += strlen(key) - 1;
				++i;
			}
			continue;
		}

		expandedfilter[j] = filter[i];
	}

	return xstrdup(expandedfilter, "table_ldap_expandfilter");
}

static struct aldap *
ldap_client_connect(const char *addr)
{
	struct aldap_url	lu;
	struct addrinfo		 hints, *res0, *res;
	int			 error;

	char *url;
	int fd = -1;

	if ((url = strdup(addr)) == NULL)
		err(1, NULL);

	if (aldap_parse_url(url, &lu) != 1) {
		warnx("aldap_parse_url fail");
		goto err;
	}

	bzero(&hints, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM; /* DUMMY */
	error = getaddrinfo(lu.host, NULL, &hints, &res0);
	if (error == EAI_AGAIN || error == EAI_NODATA || error == EAI_NONAME)
		goto err;
	if (error) {
		log_warnx("ldap_client_connect: could not parse \"%s\": %s", lu.host,
		    gai_strerror(error));
		goto err;
	}

	for (res = res0; res; res = res->ai_next) {
		if (res->ai_family != AF_INET && res->ai_family != AF_INET6)
			continue;

		fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (fd == -1)
			continue;

		if (res->ai_family == AF_INET) {
			struct sockaddr_in sin4 = *(struct sockaddr_in *)res->ai_addr;
			sin4.sin_port = htons(lu.port);
			if (connect(fd, (struct sockaddr *)&sin4, res->ai_addrlen) == 0)
				return aldap_init(fd);
		}
		else if (res->ai_family == AF_INET6) {
			struct sockaddr_in6 sin6 = *(struct sockaddr_in6 *)res->ai_addr;
			sin6.sin6_port = htons(lu.port);
			if (connect(fd, (struct sockaddr *)&sin6, res->ai_addrlen) == 0)
				return aldap_init(fd);
		}

		close(fd);
	}

err:
	if (fd != -1)
		close(fd);
	free(url);
	return NULL;
}
