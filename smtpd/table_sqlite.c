/*	$OpenBSD$	*/

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
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "smtpd.h"
#include "log.h"

/* sqlite(3) backend */
static int table_sqlite_config(struct table *, const char *);
static int table_sqlite_update(struct table *);
static void *table_sqlite_open(struct table *);
static int table_sqlite_lookup(void *, const char *, enum table_service,
    void **);
static void  table_sqlite_close(void *);

struct table_backend table_backend_sqlite = {
	K_ALIAS|K_DOMAIN|K_USERINFO/*|K_CREDENTIALS|K_NETADDR,*/,
	table_sqlite_config,
	table_sqlite_open,
	table_sqlite_update,
	table_sqlite_close,
	table_sqlite_lookup,
};

struct table_sqlite_handle {
	sqlite3	        *ppDb;	
	struct table	*table;
};

static int table_sqlite_alias(struct table_sqlite_handle *, const char *, void **);
static int table_sqlite_domain(struct table_sqlite_handle *, const char *, void **);
static int table_sqlite_userinfo(struct table_sqlite_handle *, const char *, void **);

static int
table_sqlite_config(struct table *table, const char *config)
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
	if (table_get(cfg, "dbpath") == NULL) {
		log_warnx("table_sqlite: missing 'dbpath' configuration");
		return 0;
	}

	table_set_config(table, cfg);
	return 1;

err:
	table_destroy(cfg);
	return 0;
}

static int
table_sqlite_update(struct table *table)
{
	log_info("info: Table \"%s\" successfully updated", table->t_name);
	return 1;
}

static void *
table_sqlite_open(struct table *table)
{
	struct table_sqlite_handle	*tsh;
	struct table	*cfg;
	const char	*dbpath;

	tsh = xcalloc(1, sizeof *tsh, "table_sqlite_open");
	tsh->table = table;

	cfg = table_get_config(table);
	dbpath = table_get(cfg, "dbpath");

	if (sqlite3_open(dbpath, &tsh->ppDb) != SQLITE_OK) {
		log_warnx("table_sqlite: open: %s", sqlite3_errmsg(tsh->ppDb));
		return NULL;
	}

	return tsh;
}

static void
table_sqlite_close(void *hdl)
{
	return;
}

static int
table_sqlite_lookup(void *hdl, const char *key, enum table_service service,
    void **retp)
{
	struct table_sqlite_handle	*tsh = hdl;

	switch (service) {
	case K_ALIAS:
		return table_sqlite_alias(tsh, key, retp);
	case K_DOMAIN:
		return table_sqlite_domain(tsh, key, retp);
	case K_USERINFO:
		return table_sqlite_domain(tsh, key, retp);
	default:
		log_warnx("table_sqlite: lookup: unsupported lookup service");
		return -1;
	}

	return 0;
}

static int
table_sqlite_credentials(const char *key, char *line, size_t len, void **retp)
{
	return 0;
}

static int
table_sqlite_alias(struct table_sqlite_handle *tsh, const char *key, void **retp)
{
	struct table	       *cfg = table_get_config(tsh->table);
	const char	       *query = table_get(cfg, "query_alias");
	sqlite3_stmt	       *stmt;
	struct table_alias     *table_alias = NULL;
	struct expandnode	xn;
	
	if (query == NULL) {
		log_warnx("table_sqlite: lookup: no query configured for aliases");
		return -1;
	}

	if (sqlite3_prepare_v2(tsh->ppDb, query, -1, &stmt, 0) != SQLITE_OK) {
		log_warnx("table_sqlite: prepare: %s", sqlite3_errmsg(tsh->ppDb));
		return -1;
	}

	if (sqlite3_column_count(stmt) != 1) {
		log_warnx("table_sqlite: columns: invalid resultset");
		sqlite3_finalize(stmt);
		return -1;
	}

	if (retp)
		table_alias = xcalloc(1, sizeof *table_alias, "table_sqlite_alias");

	sqlite3_bind_text(stmt, 1, key, strlen(key), NULL);
	while (sqlite3_step(stmt) == SQLITE_ROW) {
		if (retp == NULL) {
			sqlite3_finalize(stmt);
			return 1;
		}
		if (! alias_parse(&xn, sqlite3_column_text(stmt, 0)))
			goto error;
		expand_insert(&table_alias->expand, &xn);
		table_alias->nbnodes++;
		
	}
	sqlite3_finalize(stmt);
	*retp = table_alias;
	return table_alias->nbnodes;

error:
	*retp = NULL;
	expand_free(&table_alias->expand);
	free(table_alias);
	return -1;
}

static int
table_sqlite_netaddr(const char *key, char *line, size_t len, void **retp)
{
	return 0;
}

static int
table_sqlite_domain(struct table_sqlite_handle *tsh, const char *key, void **retp)
{
	struct table	       *cfg = table_get_config(tsh->table);
	const char	       *query = table_get(cfg, "query_domain");
	sqlite3_stmt	       *stmt;
	struct table_domain    *domain = NULL;
	
	if (query == NULL) {
		log_warnx("table_sqlite: lookup: no query configured for domain");
		return -1;
	}

	if (sqlite3_prepare_v2(tsh->ppDb, query, -1, &stmt, 0) != SQLITE_OK) {
		log_warnx("table_sqlite: prepare: %s", sqlite3_errmsg(tsh->ppDb));
		return -1;
	}

	if (sqlite3_column_count(stmt) != 1) {
		log_warnx("table_sqlite: columns: invalid resultset");
		sqlite3_finalize(stmt);
		return -1;
	}

	sqlite3_bind_text(stmt, 1, key, strlen(key), NULL);

	switch (sqlite3_step(stmt)) {
	case SQLITE_ROW:
		if (retp) {
			domain = xcalloc(1, sizeof *domain, "table_sqlite_domain");
			strlcpy(domain->name, sqlite3_column_text(stmt, 0), sizeof domain->name);
			*retp = domain;
		}
		sqlite3_finalize(stmt);
		return 1;

	case SQLITE_DONE:
		sqlite3_finalize(stmt);
		return 0;

	default:
		sqlite3_finalize(stmt);
	}

	free(domain);
	if (retp)
		*retp = NULL;
	return -1;
}

static int
table_sqlite_userinfo(struct table_sqlite_handle *tsh, const char *key, void **retp)
{
	struct table	       *cfg = table_get_config(tsh->table);
	const char	       *query = table_get(cfg, "query_user");
	sqlite3_stmt	       *stmt;
	struct userinfo	       *userinfo = NULL;
	size_t			s;
	
	if (query == NULL) {
		log_warnx("table_sqlite: lookup: no query configured for user");
		return -1;
	}

	if (sqlite3_prepare_v2(tsh->ppDb, query, -1, &stmt, 0) != SQLITE_OK) {
		log_warnx("table_sqlite: prepare: %s", sqlite3_errmsg(tsh->ppDb));
		return -1;
	}

	if (sqlite3_column_count(stmt) != 5) {
		log_warnx("table_sqlite: columns: invalid resultset");
		sqlite3_finalize(stmt);
		return -1;
	}

	sqlite3_bind_text(stmt, 1, key, strlen(key), NULL);

	switch (sqlite3_step(stmt)) {
	case SQLITE_ROW:
		if (retp) {
			userinfo = xcalloc(1, sizeof *userinfo, "table_sqlite_userinfo");
			s = strlcpy(userinfo->username, sqlite3_column_text(stmt, 0),
			    sizeof(userinfo->username));
			if (s >= sizeof(userinfo->username))
				goto error;
			userinfo->uid = sqlite3_column_int(stmt, 2);
			userinfo->gid = sqlite3_column_int(stmt, 3);
			s = strlcpy(userinfo->directory, sqlite3_column_text(stmt, 4),
			    sizeof(userinfo->directory));
			if (s >= sizeof(userinfo->directory))
				goto error;
			*retp = userinfo;
		}
		sqlite3_finalize(stmt);
		return 1;

	case SQLITE_DONE:
		sqlite3_finalize(stmt);
		return 0;

	default:
		goto error;
	}

error:
	sqlite3_finalize(stmt);
	free(userinfo);
	if (retp)
		*retp = NULL;
	return -1;
}
