/*	$OpenBSD: table_sqlite.c,v 1.2 2013/01/31 18:34:43 eric Exp $	*/

/*
 * Copyright (c) 2013 Eric Faurot <eric@openbsd.org>
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

#include "includes.h"

#include <sys/types.h>

#include <ctype.h>
#include <fcntl.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "smtpd-defines.h"
#include "smtpd-api.h"
#include "log.h"

enum {
	SQL_ALIAS = 0,
	SQL_DOMAIN,
	SQL_CREDENTIALS,
	SQL_NETADDR,
	SQL_USERINFO,
	SQL_SOURCE,
	SQL_MAILADDR,
	SQL_ADDRNAME,

	SQL_MAX
};

static int table_sqlite_update(void);
static int table_sqlite_lookup(int, const char *, char *, size_t);
static int table_sqlite_check(int, const char *);
static int table_sqlite_fetch(int, char *, size_t);

static sqlite3_stmt *table_sqlite_query(const char *, int);

static char		*config;
static sqlite3		*db;
static sqlite3_stmt	*statements[SQL_MAX];

int
main(int argc, char **argv)
{
	int	ch;

	log_init(1);

	config = NULL;

	while ((ch = getopt(argc, argv, "f:")) != -1) {
		switch (ch) {
		case 'f':
			config = optarg;
			break;
		default:
			log_warnx("warn: backend-table-sqlite: bad option");
			return (1);
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;

	if (config == NULL) {
		log_warnx("warn: backend-table-sqlite: config file not specified");
		return (1);
	}

	if (argc != 0) {
		log_warnx("warn: backend-table-sqlite: bogus argument(s)");
		return (1);
	}

	if (table_sqlite_update() == 0) {
		log_warnx("warn: backend-table-sqlite: error parsing config file");
		return (1);
	}

	table_api_on_update(table_sqlite_update);
	table_api_on_check(table_sqlite_check);
	table_api_on_lookup(table_sqlite_lookup);
	table_api_on_fetch(table_sqlite_fetch);
	table_api_dispatch();

	return (0);
}

static sqlite3_stmt *
table_sqlite_query(const char *key, int service)
{
	int		 i;
	sqlite3_stmt	*stmt;

	stmt = NULL;
	for(i = 0; i < SQL_MAX; i++)
		if (service == 1 << i) {
			stmt = statements[i];
			break;
		}

	if (stmt == NULL)
		return (NULL);

	sqlite3_bind_text(stmt, 1, key, strlen(key), NULL);

	return (stmt);
}

static int
table_sqlite_update(void)
{
	static const struct {
		const char	*name;
		int		 cols;
	} qspec[SQL_MAX] = {
		{ "query_alias",	1 },
		{ "query_domain",	1 },
		{ "query_credentials",	2 },
		{ "query_netaddr",	1 },
		{ "query_userinfo",	4 },
		{ "query_source",	1 },
		{ "query_mailaddr",	1 },
		{ "query_addrname",	1 },
	};
	sqlite3		*_db;
	sqlite3_stmt	*_statements[SQL_MAX];
	char		*queries[SQL_MAX];
	size_t		 flen;
	FILE		*fp;
	char		*key, *value, *buf, *lbuf, *dbpath;
	int		 i, ret;

	dbpath = NULL;
	_db = NULL;
	bzero(queries, sizeof(queries));
	bzero(_statements, sizeof(_statements));

	ret = 0;

	/* Parse configuration */

	fp = fopen(config, "r");
	if (fp == NULL)
		return (0);

	lbuf = NULL;
	while ((buf = fgetln(fp, &flen))) {
		if (buf[flen - 1] == '\n')
			buf[flen - 1] = '\0';
		else {
			lbuf = malloc(flen + 1);
			if (lbuf == NULL) {
				log_warn("warn: backend-table-sqlite: malloc");
				return (0);
			}
			memcpy(lbuf, buf, flen);
			lbuf[flen] = '\0';
			buf = lbuf;
		}

		key = buf;
		while (isspace((int)*key))
			++key;
		if (*key == '\0' || *key == '#')
			continue;
		value = key;
		strsep(&value, " \t:");
		if (value) {
			while (*value) {
				if (!isspace(*value) &&
				    !(*value == ':' && isspace(*(value + 1))))
					break;
				++value;
			}
			if (*value == '\0')
				value = NULL;
		}

		if (value == NULL) {
			log_warnx("warn: backend-table-sqlite: missing value for key %s", key);
			continue;
		}

		if (!strcmp("dbpath", key)) {
			if (dbpath) {
				log_warnx("warn: backend-table-sqlite: duplicate dbpath %s", value);
				free(dbpath);
			}
			dbpath = strdup(value);
			if (dbpath == NULL) {
				log_warn("warn: backend-table-sqlite: strdup");
				goto end;
			}
			continue;
		}

		for(i = 0; i < SQL_MAX; i++)
			if (!strcmp(qspec[i].name, key))
				break;
		if (i == SQL_MAX) {
			log_warnx("warn: backend-table-sqlite: bogus key %s", key);
			continue;
		}

		if (queries[i]) {
			log_warnx("warn: backend-table-sqlite: duplicate key %s", key);
			continue;
		}

		queries[i] = strdup(value);
		if (queries[i] == NULL) {
			log_warnx("warn: backend-table-sqlite: strdup");
			goto end;
		}
	}

	/* Setup db */

	log_debug("debug: backend-table-sqlite: opening %s", dbpath);

	if (sqlite3_open(dbpath, &_db) != SQLITE_OK) {
		log_warnx("warn: backend-table-sqlite: open: %s",
		    sqlite3_errmsg(_db));
		goto end;
	}

	for (i = 0; i < SQL_MAX; i++) {
		if (queries[i] == NULL)
			continue;
		if (sqlite3_prepare_v2(_db, queries[i], -1, &_statements[i], 0)
		    != SQLITE_OK) {
			log_warnx("warn: backend-table-sqlite: prepare: %s",
			    sqlite3_errmsg(_db));
			goto end;
		}
		if (sqlite3_column_count(_statements[i]) != qspec[i].cols) {
			log_warnx("warn: backend-table-sqlite: columns: invalid resultset");
			goto end;
		}
	}

	/* Replace previous setup */

	for (i = 0; i < SQL_MAX; i++) {
		if (statements[i])
			sqlite3_finalize(statements[i]);
		statements[i] = _statements[i];
		_statements[i] = NULL;
	}
	if (db)
		sqlite3_close(_db);
	db = _db;
	_db = NULL;

	log_debug("debug: backend-table-sqlite: config successfully updated");
	ret = 1;

    end:

	/* Cleanup */
	for (i = 0; i < SQL_MAX; i++) {
		if (_statements[i])
			sqlite3_finalize(_statements[i]);
		free(queries[i]);
	}
	if (_db)
		sqlite3_close(_db);

	free(lbuf);
	fclose(fp);
	return (ret);
}

static int
table_sqlite_check(int service, const char *key)
{
	sqlite3_stmt	*stmt;
	int		 r;

	stmt = table_sqlite_query(key, service);
	if (stmt == NULL)
		return (-1);

	r = sqlite3_step(stmt);
	sqlite3_reset(stmt);

	if (r == SQLITE_ROW)
		return (1);

	if (r == SQLITE_DONE)
		return (0);

	return (-1);
}

static int
table_sqlite_lookup(int service, const char *key, char *dst, size_t sz)
{
	sqlite3_stmt	*stmt;
	const char	*value;
	int		 r, s;

	stmt = table_sqlite_query(key, service);
	if (stmt == NULL)
		return (-1);

	s = sqlite3_step(stmt);
	if (s == SQLITE_DONE) {
		sqlite3_reset(stmt);
		return (0);
	}

	if (s != SQLITE_ROW) {
		sqlite3_reset(stmt);
		return (-1);
	}

	r = 1;

	switch(service) {
	case K_ALIAS:

		do {
			value = sqlite3_column_text(stmt, 0);
			if (dst[0] && strlcat(dst, ", ", sz) >= sz) {
				r = -1;
				break;
			}
			if (strlcat(dst, value, sz) >= sz) {
				r = -1;
				break;
			}
			s = sqlite3_step(stmt);

		} while (s == SQLITE_ROW); 

		if (s != SQLITE_DONE)
			r = -1;
		break;
	case K_CREDENTIALS:
		if (snprintf(dst, sz, "%s:%s",
		    sqlite3_column_text(stmt, 0),
		    sqlite3_column_text(stmt, 1)) > (ssize_t)sz)
			r = -1;
		break;
	case K_USERINFO:
		if (snprintf(dst, sz, "%s:%i:%i:%s",
		    sqlite3_column_text(stmt, 0),
		    sqlite3_column_int(stmt, 1),
		    sqlite3_column_int(stmt, 2),
		    sqlite3_column_text(stmt, 3)) > (ssize_t)sz)
			r = -1;
		break;
	case K_DOMAIN:
	case K_NETADDR:
	case K_SOURCE:
	case K_MAILADDR:
	case K_ADDRNAME:
		if (strlcpy(dst, sqlite3_column_text(stmt, 0), sz) >= sz)
			r = -1;
		break;
	default:
		r = -1;
	}

	return (r);
}

static int
table_sqlite_fetch(int service, char *dst, size_t sz)
{
	return (-1);
}
