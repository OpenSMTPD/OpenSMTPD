/*	$OpenBSD: map_db.c,v 1.12 2012/11/12 14:58:53 eric Exp $	*/

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

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/param.h>
#include <sys/socket.h>

#include <db.h>
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


/* db(3) backend */
static int table_db_config(struct table *, const char *);
static int table_db_update(struct table *, const char *);
static void *table_db_open(struct table *);
static void *table_db_lookup(void *, const char *, enum table_service);
static int   table_db_compare(void *, const char *, enum table_service,
    int (*)(const char *, const char *));
static void  table_db_close(void *);

static char *table_db_get_entry(void *, const char *, size_t *);
static void *table_db_credentials(const char *, char *, size_t);
static void *table_db_alias(const char *, char *, size_t);
static void *table_db_virtual(const char *, char *, size_t);
static void *table_db_netaddr(const char *, char *, size_t);


struct table_backend table_backend_db = {
	K_ALIAS|K_VIRTUAL|K_CREDENTIALS|K_NETADDR,
	table_db_config,
	table_db_open,
	table_db_update,
	table_db_close,
	table_db_lookup,
	table_db_compare
};


static int
table_db_config(struct table *table, const char *config)
{
	return 1;
}

static int
table_db_update(struct table *table, const char *config)
{
	return 1;
}

static void *
table_db_open(struct table *table)
{
	return dbopen(table->t_config, O_RDONLY, 0600, DB_HASH, NULL);
}

static void
table_db_close(void *hdl)
{
	DB *db = hdl;

	db->close(db);
}

static void *
table_db_lookup(void *hdl, const char *key, enum table_service kind)
{
	char *line;
	size_t len;
	void *ret;

	line = table_db_get_entry(hdl, key, &len);
	if (line == NULL)
		return NULL;

	ret = 0;
	switch (kind) {
	case K_ALIAS:
		ret = table_db_alias(key, line, len);
		break;

	case K_CREDENTIALS:
		ret = table_db_credentials(key, line, len);
		break;

	case K_VIRTUAL:
		ret = table_db_virtual(key, line, len);
		break;

	case K_NETADDR:
		ret = table_db_netaddr(key, line, len);
		break;

	default:
		break;
	}

	free(line);

	return ret;
}

static int
table_db_compare(void *hdl, const char *key, enum table_service kind,
    int (*func)(const char *, const char *))
{
	int ret = 0;
	DB *db = hdl;
	DBT dbk;
	DBT dbd;
	int r;
	char *buf = NULL;

	for (r = db->seq(db, &dbk, &dbd, R_FIRST); !r;
	     r = db->seq(db, &dbk, &dbd, R_NEXT)) {
		buf = xmemdup(dbk.data, dbk.size + 1, "table_db_compare");
		log_debug("debug: key: %s, buf: %s", key, buf);
		if (func(key, buf))
			ret = 1;
		free(buf);
		if (ret)
			break;
	}
	return ret;
}

static char *
table_db_get_entry(void *hdl, const char *key, size_t *len)
{
	int ret;
	DBT dbk;
	DBT dbv;
	DB *db = hdl;
	char pkey[MAX_LINE_SIZE];

	/* workaround the stupidity of the DB interface */
	if (strlcpy(pkey, key, sizeof pkey) >= sizeof pkey)
		errx(1, "table_db_get_entry: key too long");
	dbk.data = pkey;
	dbk.size = strlen(pkey) + 1;

	if ((ret = db->get(db, &dbk, &dbv, 0)) != 0)
		return NULL;

	*len = dbv.size;

	return xmemdup(dbv.data, dbv.size, "table_db_get_entry");
}

static void *
table_db_credentials(const char *key, char *line, size_t len)
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
	    "table_db_credentials");

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
table_db_alias(const char *key, char *line, size_t len)
{
	char	       	*subrcpt;
	char	       	*endp;
	struct table_alias	*table_alias = NULL;
	struct expandnode	 xn;

	table_alias = xcalloc(1, sizeof *table_alias, "table_db_alias");

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
table_db_virtual(const char *key, char *line, size_t len)
{
	char	       	*subrcpt;
	char	       	*endp;
	struct table_virtual	*table_virtual = NULL;
	struct expandnode	 xn;

	table_virtual = xcalloc(1, sizeof *table_virtual, "table_db_virtual");

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
table_db_netaddr(const char *key, char *line, size_t len)
{
	struct table_netaddr	*table_netaddr = NULL;

	table_netaddr = xcalloc(1, sizeof *table_netaddr, "table_db_netaddr");

	if (! text_to_netaddr(&table_netaddr->netaddr, line))
	    goto error;

	return table_netaddr;

error:
	free(table_netaddr);
	return NULL;
}
