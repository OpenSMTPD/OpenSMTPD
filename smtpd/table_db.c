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
#include <sys/stat.h>
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
static int table_db_update(struct table *);
static void *table_db_open(struct table *);
static int table_db_lookup(void *, const char *, enum table_service, void **);
static void  table_db_close(void *);

static char *table_db_get_entry(void *, const char *, size_t *);
static char *table_db_get_entry_match(void *, const char *, size_t *,
    int(*)(const char *, const char *));

static int table_db_credentials(const char *, char *, size_t, void **);
static int table_db_alias(const char *, char *, size_t, void **);
static int table_db_domain(const char *, char *, size_t, void **);
static int table_db_netaddr(const char *, char *, size_t, void **);

struct table_backend table_backend_db = {
	K_ALIAS|K_DOMAIN|K_CREDENTIALS|K_NETADDR,
	table_db_config,
	table_db_open,
	table_db_update,
	table_db_close,
	table_db_lookup,
};

static struct keycmp {
	enum table_service	service;
	int		       (*func)(const char *, const char *);
} keycmp[] = {
	{ K_NETADDR, table_netaddr_match }
};

struct dbhandle {
	DB		*db;
	char		 pathname[MAXPATHLEN];
	time_t		 mtime;
	struct table	*table;
};

static int
table_db_config(struct table *table, const char *config)
{
	DB	*db;

	db = table_db_open(table);
	if (db == NULL)
		return 0;

	table_db_close(db);
	return 1;
}

static int
table_db_update(struct table *table)
{
	struct dbhandle	*handle;

	handle = table_db_open(table);
	if (handle == NULL)
		return 0;

	table_db_close(table->t_handle);
	free(table->t_handle);
	table->t_handle = handle;
	return 1;
}

static void *
table_db_open(struct table *table)
{
	struct dbhandle	       *handle;
	struct stat		sb;

	handle = xcalloc(1, sizeof *handle, "table_db_open");
	if (strlcpy(handle->pathname, table->t_config, sizeof handle->pathname)
	    >= sizeof handle->pathname)
		goto error;

	if (stat(handle->pathname, &sb) < 0)
		goto error;

	handle->mtime = sb.st_mtime;
	handle->db = dbopen(table->t_config, O_RDONLY, 0600, DB_HASH, NULL);
	if (handle->db == NULL)
		goto error;
	handle->table = table;

	return handle;

error:
	if (handle->db)
		handle->db->close(handle->db);
	free(handle);
	return NULL;
}

static void
table_db_close(void *hdl)
{
	struct dbhandle	*handle = hdl;
	handle->db->close(handle->db);
}

static int
table_db_lookup(void *hdl, const char *key, enum table_service service,
    void **retp)
{
	struct dbhandle	*handle = hdl;
	char	       *line;
	size_t		len = 0;
	int		ret;
	int	       (*match)(const char *, const char *) = NULL;
	size_t		i;
	struct stat	sb;

	if (stat(handle->pathname, &sb) < 0)
		return -1;

	/* DB has changed, close and reopen */
	if (sb.st_mtime != handle->mtime)
		table_db_update(handle->table);

	for (i = 0; i < nitems(keycmp); ++i)
		if (keycmp->service == service)
			match = keycmp->func;

	if (match == NULL)
		line = table_db_get_entry(hdl, key, &len);
	else
		line = table_db_get_entry_match(hdl, key, &len, match);
	if (line == NULL)
		return 0;

	if (retp == NULL)
		return 1;

	ret = 0;
	switch (service) {
	case K_ALIAS:
		ret = table_db_alias(key, line, len, retp);
		break;

	case K_CREDENTIALS:
		ret = table_db_credentials(key, line, len, retp);
		break;

	case K_DOMAIN:
		ret = table_db_domain(key, line, len, retp);
		break;

	case K_NETADDR:
		ret = table_db_netaddr(key, line, len, retp);
		break;

	default:
		break;
	}

	free(line);

	return ret;
}


static char *
table_db_get_entry_match(void *hdl, const char *key, size_t *len,
    int(*func)(const char *, const char *))
{
	struct dbhandle	*handle = hdl;
	DBT dbk;
	DBT dbd;
	int r;
	char *buf = NULL;

	for (r = handle->db->seq(handle->db, &dbk, &dbd, R_FIRST); !r;
	     r = handle->db->seq(handle->db, &dbk, &dbd, R_NEXT)) {
		buf = xmemdup(dbk.data, dbk.size, "table_db_get_entry_cmp");
		if (func(key, buf)) {
			*len = dbk.size;
			return buf;
		}
		free(buf);
	}
	return NULL;
}

static char *
table_db_get_entry(void *hdl, const char *key, size_t *len)
{
	struct dbhandle	*handle = hdl;
	int ret;
	DBT dbk;
	DBT dbv;
	char pkey[MAX_LINE_SIZE];

	/* workaround the stupidity of the DB interface */
	if (strlcpy(pkey, key, sizeof pkey) >= sizeof pkey)
		errx(1, "table_db_get_entry: key too long");
	dbk.data = pkey;
	dbk.size = strlen(pkey) + 1;

	if ((ret = handle->db->get(handle->db, &dbk, &dbv, 0)) != 0)
		return NULL;

	*len = dbv.size;

	return xmemdup(dbv.data, dbv.size, "table_db_get_entry");
}

static int
table_db_credentials(const char *key, char *line, size_t len, void **retp)
{
	struct table_credentials *credentials = NULL;
	char *p;

	/* credentials are stored as user:password */
	if (len < 3)
		return -1;

	/* too big to fit in a smtp session line */
	if (len >= MAX_LINE_SIZE)
		return -1;

	p = strchr(line, ':');
	if (p == NULL)
		return -1;

	if (p == line || p == line + len - 1)
		return -1;
	*p++ = '\0';

	credentials = xcalloc(1, sizeof *credentials,
	    "table_db_credentials");
	if (strlcpy(credentials->username, line, sizeof(credentials->username))
	    >= sizeof(credentials->username))
		goto err;

	if (strlcpy(credentials->password, p, sizeof(credentials->password))
	    >= sizeof(credentials->password))
		goto err;

	*retp = credentials;
	return 1;

err:
	*retp = NULL;
	free(credentials);
	return -1;
}

static int
table_db_alias(const char *key, char *line, size_t len, void **retp)
{
	char		*subrcpt;
	char		*endp;
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
	*retp = table_alias;
	return 1;

error:
	*retp = NULL;
	expand_free(&table_alias->expand);
	free(table_alias);
	return -1;
}

static int
table_db_netaddr(const char *key, char *line, size_t len, void **retp)
{
	struct table_netaddr	*table_netaddr = NULL;

	table_netaddr = xcalloc(1, sizeof *table_netaddr, "table_db_netaddr");

	if (! text_to_netaddr(&table_netaddr->netaddr, line))
		goto error;

	*retp = table_netaddr;
	return 1;

error:
	*retp = NULL;
	free(table_netaddr);
	return 0;
}

static int
table_db_domain(const char *key, char *line, size_t len, void **retp)
{
	struct table_domain	*domain = NULL;

	domain = xcalloc(1, sizeof *domain, "table_db_domain");

	if (strlcpy(domain->name, line, sizeof domain->name)
	    >= sizeof domain->name)
		goto error;

	*retp = domain;
	return 1;

error:
	*retp = NULL;
	free(domain);
	return 0;
}
