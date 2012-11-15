/*	$OpenBSD: map_static.c,v 1.9 2012/11/12 14:58:53 eric Exp $	*/

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

#include <ctype.h>
#include <err.h>
#include <event.h>
#include <fcntl.h>
#include <imsg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "smtpd.h"
#include "log.h"


/* static backend */
static int table_static_config(struct table *, const char *);
static int table_static_update(struct table *, const char *);
static void *table_static_open(struct table *);
static void *table_static_lookup(void *, const char *, enum table_service);
static int   table_static_compare(void *, const char *, enum table_service,
    int(*)(const char *, const char *));
static void  table_static_close(void *);

static void *table_static_credentials(const char *, char *, size_t);
static void *table_static_alias(const char *, char *, size_t);
static void *table_static_virtual(const char *, char *, size_t);
static void *table_static_netaddr(const char *, char *, size_t);

struct table_backend table_backend_static = {
	K_ALIAS|K_VIRTUAL|K_CREDENTIALS|K_NETADDR,
	table_static_config,
	table_static_open,
	table_static_update,
	table_static_close,
	table_static_lookup,
	table_static_compare
};

static int
table_static_config(struct table *table, const char *config)
{
	/* no config ? ok */
	if (config == NULL)
		return 1;

	return table_config_parser(table, config);
}

static int
table_static_update(struct table *table, const char *config)
{
	struct table   *t;
	char		name[MAX_LINE_SIZE];

	/* no config ? ok */
	if (config == NULL)
		goto ok;

	t = table_create(table->t_src, NULL, config);
	if (! t->t_backend->config(t, config))
		goto err;

	/* update successful, swap table names */
	strlcpy(name, table->t_name, sizeof name);
	strlcpy(table->t_name, t->t_name, sizeof table->t_name);
	strlcpy(t->t_name, name, sizeof t->t_name);

	/* swap, table id */
	table->t_id = table->t_id ^ t->t_id;
	t->t_id     = table->t_id ^ t->t_id;
	table->t_id = table->t_id ^ t->t_id;

	/* destroy former table */
	table_destroy(table);

ok:
	log_info("info: Table \"%s\" successfully updated", name);
	return 1;

err:
	table_destroy(t);
	log_info("info: Failed to update table \"%s\"", name);
	return 0;
}

static void *
table_static_open(struct table *table)
{
	return table;
}

static void
table_static_close(void *hdl)
{
	return;
}

static void *
table_static_lookup(void *hdl, const char *key, enum table_service kind)
{
	struct table	*m  = hdl;
	struct mapel	*me = NULL;
	char		*line;
	void		*ret;
	size_t		 len;

	line = NULL;
	TAILQ_FOREACH(me, &m->t_contents, me_entry) {
		if (strcmp(key, me->me_key) == 0) {
			if (me->me_val == NULL)
				return NULL;
			line = strdup(me->me_val);
			break;
		}
	}

	if (line == NULL)
		return NULL;

	len = strlen(line);
	switch (kind) {
	case K_ALIAS:
		ret = table_static_alias(key, line, len);
		break;

	case K_CREDENTIALS:
		ret = table_static_credentials(key, line, len);
		break;

	case K_VIRTUAL:
		ret = table_static_virtual(key, line, len);
		break;

	case K_NETADDR:
		ret = table_static_netaddr(key, line, len);
		break;

	default:
		ret = NULL;
		break;
	}

	free(line);

	return ret;
}

static int
table_static_compare(void *hdl, const char *key, enum table_service kind,
    int(*func)(const char *, const char *))
{
	struct table	*m   = hdl;
	struct mapel	*me  = NULL;
	int		 ret = 0;

	TAILQ_FOREACH(me, &m->t_contents, me_entry) {
		if (! func(key, me->me_key))
			continue;
		ret = 1;
		break;
	}

	return ret;
}

static void *
table_static_credentials(const char *key, char *line, size_t len)
{
	struct table_credentials *table_credentials = NULL;
	char *p;

	/* credentials are stored as user:password */
	if (len < 3)
		return NULL;

	/* too big to fit in a smtp session line */
	if (len >= MAX_LINE_SIZE)
		return NULL;

	p = strchr(line, ':');
	if (p == NULL)
		return NULL;

	if (p == line || p == line + len - 1)
		return NULL;
	*p++ = '\0';

	table_credentials = xcalloc(1, sizeof *table_credentials,
	    "table_static_credentials");

	if (strlcpy(table_credentials->username, line,
		sizeof(table_credentials->username)) >=
	    sizeof(table_credentials->username))
		goto err;

	if (strlcpy(table_credentials->password, p,
		sizeof(table_credentials->password)) >=
	    sizeof(table_credentials->password))
		goto err;

	return table_credentials;

err:
	free(table_credentials);
	return NULL;
}

static void *
table_static_alias(const char *key, char *line, size_t len)
{
	char			*subrcpt;
	char			*endp;
	struct table_alias	*table_alias = NULL;
	struct expandnode	 xn;

	table_alias = xcalloc(1, sizeof *table_alias, "table_static_alias");

	while ((subrcpt = strsep(&line, ",")) != NULL) {
		/* subrcpt: strip initial whitespace. */
		while (isspace((int)*subrcpt))
			++subrcpt;
		if (*subrcpt == '\0')
			goto error;

		/* subrcpt: strip trailing whitespace. */
		endp = subrcpt + strlen(subrcpt) - 1;
		while (subrcpt < endp && isspace((int)*endp))
			*endp-- = '\0';

		if (! alias_parse(&xn, subrcpt))
			goto error;

		expand_insert(&table_alias->expand, &xn);
		table_alias->nbnodes++;
	}

	return table_alias;

error:
	expand_free(&table_alias->expand);
	free(table_alias);
	return NULL;
}

static void *
table_static_virtual(const char *key, char *line, size_t len)
{
	char			*subrcpt;
	char			*endp;
	struct table_virtual	*table_virtual = NULL;
	struct expandnode	 xn;

	table_virtual = xcalloc(1, sizeof *table_virtual,
	    "table_static_virtual");

	/* domain key, discard value */
	if (strchr(key, '@') == NULL)
		return table_virtual;

	while ((subrcpt = strsep(&line, ",")) != NULL) {
		/* subrcpt: strip initial whitespace. */
		while (isspace((int)*subrcpt))
			++subrcpt;
		if (*subrcpt == '\0')
			goto error;

		/* subrcpt: strip trailing whitespace. */
		endp = subrcpt + strlen(subrcpt) - 1;
		while (subrcpt < endp && isspace((int)*endp))
			*endp-- = '\0';

		if (! alias_parse(&xn, subrcpt))
			goto error;

		expand_insert(&table_virtual->expand, &xn);
		table_virtual->nbnodes++;
	}

	return table_virtual;

error:
	expand_free(&table_virtual->expand);
	free(table_virtual);
	return NULL;
}


static void *
table_static_netaddr(const char *key, char *line, size_t len)
{
	struct table_netaddr	*table_netaddr = NULL;

	table_netaddr = xcalloc(1, sizeof *table_netaddr,
	    "table_static_netaddr");

	if (! text_to_netaddr(&table_netaddr->netaddr, line))
	    goto error;

	return table_netaddr;

error:
	free(table_netaddr);
	return NULL;
}
