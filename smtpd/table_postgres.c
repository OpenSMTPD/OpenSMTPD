/*	$OpenBSD$	*/

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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <postgresql/libpq-fe.h>

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

static int table_postgres_update(void);
static int table_postgres_lookup(int, const char *, char *, size_t);
static int table_postgres_check(int, const char *);
static int table_postgres_fetch(int, char *, size_t);

static PGresult *table_postgres_query(const char *, int);

#define SQL_MAX_RESULT	5

#define	DEFAULT_EXPIRE	60
#define	DEFAULT_REFRESH	1000

static char		*config;
static PGconn		*db;
static char		*statements[SQL_MAX];
static char		*stmt_fetch_source;

static struct dict	 sources;
static void		*source_iter;
static size_t		 source_refresh = 1000;
static size_t		 source_ncall;
static int		 source_expire = 60;
static time_t		 source_update;

int
main(int argc, char **argv)
{
	int	ch;

	log_init(1);
	log_verbose(~0);

	while ((ch = getopt(argc, argv, "")) != -1) {
		switch (ch) {
		default:
			log_warnx("warn: table-postgres: bad option");
			return (1);
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 1) {
		log_warnx("warn: table-postgres: bogus argument(s)");
		return (1);
	}

	config = argv[0];

	dict_init(&sources);

	if (table_postgres_update() == 0) {
		log_warnx("warn: table-postgres: error parsing config file");
		return (1);
	}

	table_api_on_update(table_postgres_update);
	table_api_on_check(table_postgres_check);
	table_api_on_lookup(table_postgres_lookup);
	table_api_on_fetch(table_postgres_fetch);
	table_api_dispatch();

	return (0);
}

static int
table_postgres_getconfstr(const char *key, const char *value, char **var)
{
	if (*var) {
		log_warnx("warn: table-postgres: duplicate %s %s", key, value);
		free(*var);
	}
	*var = strdup(value);
	if (*var == NULL) {
		log_warn("warn: table-postgres: strdup");
		return (-1);
	}
	return (0);
}

static char *
table_postgres_prepare_stmt(PGconn *_db, const char *query, int nparams,
    unsigned int nfields)
{
	static unsigned int	 n = 0;
	PGresult		*res;
	char			*stmt;
	
	if (asprintf(&stmt, "stmt%u", n++) == -1) {
		log_warn("warn: table-postgres: asprintf");
		return (NULL);
	}

	res = PQprepare(_db, stmt, query, nparams, NULL);
	if (PQresultStatus(res) != PGRES_COMMAND_OK) {
		log_warnx("warn: table-postgres: PQprepare: %s",
		    PQerrorMessage(_db));
		free(stmt);
		stmt = NULL;
	}

	PQclear(res);
	return (stmt);
}

static int
table_postgres_update(void)
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
	PGconn		*_db;
	char		*_statements[SQL_MAX];
	char		*queries[SQL_MAX];
	char		*_stmt_fetch_source;
	char		*_query_fetch_source;
	size_t		 flen;
	size_t		 _source_refresh;
	int		 _source_expire;
	FILE		*fp;
	char		*key, *value, *buf, *lbuf;
	const char	*e;
	char		*conninfo;
	int		 i, ret;
	long long	 ll;

	conninfo = NULL;
	_db = NULL;
	bzero(queries, sizeof(queries));
	bzero(_statements, sizeof(_statements));
	_query_fetch_source = NULL;
	_stmt_fetch_source = NULL;

	_source_refresh = DEFAULT_REFRESH;
	_source_expire = DEFAULT_EXPIRE;

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
				log_warn("warn: table-postgres: malloc");
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
			log_warnx("warn: table-postgres: missing value for key %s", key);
			continue;
		}

		if (!strcmp("conninfo", key)) {
			if (table_postgres_getconfstr(key, value, &conninfo) == -1)
				goto end;
			continue;
		}
		if (!strcmp("fetch_source", key)) {
			if (table_postgres_getconfstr(key, value, &_query_fetch_source) == -1)
				goto end;
			continue;
		}
		if (!strcmp("fetch_source_expire", key)) {
			e = NULL;
			ll = strtonum(value, 0, INT_MAX, &e);
			if (e) {
				log_warnx("warn: table-postgres: bad value for %s: %s", key, e);
				goto end;
			}
			_source_expire = ll;
			continue;
		}
		if (!strcmp("fetch_source_refresh", key)) {
			e = NULL;
			ll = strtonum(value, 0, INT_MAX, &e);
			if (e) {
				log_warnx("warn: table-postgres: bad value for %s: %s", key, e);
				goto end;
			}
			_source_refresh = ll;
			continue;
		}

		for(i = 0; i < SQL_MAX; i++)
			if (!strcmp(qspec[i].name, key))
				break;
		if (i == SQL_MAX) {
			log_warnx("warn: table-postgres: bogus key %s", key);
			continue;
		}

		if (queries[i]) {
			log_warnx("warn: table-postgres: duplicate key %s", key);
			continue;
		}

		queries[i] = strdup(value);
		if (queries[i] == NULL) {
			log_warnx("warn: table-postgres: strdup");
			goto end;
		}
	}

	/* Setup db */

	log_debug("debug: table-postgres: opening %s", conninfo);

	_db = PQconnectdb(conninfo);
	if (_db == NULL) {
		log_warnx("warn: table-postgres: PQconnectdb return NULL");
		goto end;
	}
	if (PQstatus(_db) != CONNECTION_OK) {
		log_warnx("warn: table-postgres: PQconnectdb: %s",
		    PQerrorMessage(_db));
		goto end;
	}

	for (i = 0; i < SQL_MAX; i++) {
		if (queries[i] == NULL)
			continue;
		if ((_statements[i] = table_postgres_prepare_stmt(_db, queries[i], 1, qspec[i].cols)) == NULL)
			goto end;
	}

	if (_query_fetch_source &&
	    (_stmt_fetch_source = table_postgres_prepare_stmt(_db, _query_fetch_source, 0, 1)) == NULL)
		goto end;

	/* Replace previous setup */

	for (i = 0; i < SQL_MAX; i++) {
		free(statements[i]);
		statements[i] = _statements[i];
		_statements[i] = NULL;
	}
	free(stmt_fetch_source);
	stmt_fetch_source = _stmt_fetch_source;
	_stmt_fetch_source = NULL;

	if (db)
		PQfinish(_db);
	db = _db;
	_db = NULL;

	source_update = 0; /* force update */
	source_expire = _source_expire;
	source_refresh = _source_refresh;

	log_debug("debug: table-postgres: config successfully updated");
	ret = 1;

    end:

	/* Cleanup */
	for (i = 0; i < SQL_MAX; i++) {
		free(_statements[i]);
		free(queries[i]);
	}
	if (_db)
		PQfinish(_db);

	free(conninfo);
	free(_query_fetch_source);

	free(lbuf);
	fclose(fp);
	return (ret);
}

static PGresult *
table_postgres_query(const char *key, int service)
{
	PGresult	*res;
	char		*stmt;
	int		 i;

	stmt = NULL;
	for(i = 0; i < SQL_MAX; i++)
		if (service == 1 << i) {
			stmt = statements[i];
			break;
		}

	if (stmt == NULL)
		return (NULL);

	res = PQexecPrepared(db, stmt, 1, &key, NULL, NULL, 0);

	if (PQresultStatus(res) != PGRES_TUPLES_OK) {
		log_warnx("warn: table-postgres: PQexecPrepared: %s",
		    PQerrorMessage(db));
		PQclear(res);
		return (NULL);
	}

	return (res);
}

static int
table_postgres_check(int service, const char *key)
{
	PGresult	*res;
	int		 r;

	res = table_postgres_query(key, service);
	if (res == NULL)
		return (-1);

	r = (PQntuples(res) == 0) ? 0 : 1;

	PQclear(res);

	return (r);
}

static int
table_postgres_lookup(int service, const char *key, char *dst, size_t sz)
{
	PGresult	*res;
	int		 r, i;

	res = table_postgres_query(key, service);
	if (res == NULL)
		return (-1);

	if (PQntuples(res) == 0) {
		r = 0;
		goto end;
	}

	r = 1;
	switch(service) {
	case K_ALIAS:
		for (i = 0; i < PQntuples(res); i++) {
			if (dst[0] && strlcat(dst, ", ", sz) >= sz) {
				log_warnx("warn: table-postgres: result too large");
				r = -1;
				break;
			}
			if (strlcat(dst, PQgetvalue(res, i, 0), sz) >= sz) {
				log_warnx("warn: table-postgres: result too large");
				r = -1;
				break;
			}
		}
		break;
	case K_CREDENTIALS:
		if (snprintf(dst, sz, "%s:%s",
		    PQgetvalue(res, 0, 0),
 		    PQgetvalue(res, 0, 1)) > (ssize_t)sz) {
			log_warnx("warn: table-postgres: result too large");
			r = -1;
		}
		break;
	case K_USERINFO:
		if (snprintf(dst, sz, "%s:%s:%s:%s",
		    PQgetvalue(res, 0, 0),
		    PQgetvalue(res, 0, 1),
		    PQgetvalue(res, 0, 2),
		    PQgetvalue(res, 0, 3)) > (ssize_t)sz) {
			log_warnx("warn: table-postgres: result too large");
			r = -1;
		}
		break;
	case K_DOMAIN:
	case K_NETADDR:
	case K_SOURCE:
	case K_MAILADDR:
	case K_ADDRNAME:
		if (strlcpy(dst, PQgetvalue(res, 0, 0), sz) >= sz) {
			log_warnx("warn: table-postgres: result too large");
			r = -1;
		}
		break;
	default:
		log_warnx("warn: table-postgres: unknown service %i",
		    service);
		r = -1;
	}

    end:
	PQclear(res);

	return (r);
}

static int
table_postgres_fetch(int service, char *dst, size_t sz)
{
	PGresult	*res;
	const char	*k;
	int		 i;

	if (service != K_SOURCE)
		return (-1);

	if (stmt_fetch_source == NULL)
		return (-1);

	if (source_ncall < source_refresh &&
	    time(NULL) - source_update < source_expire)
	    goto fetch;

	res = PQexecPrepared(db, stmt_fetch_source, 0, NULL, NULL, NULL, 0);

	if (PQresultStatus(res) != PGRES_TUPLES_OK) {
		log_warnx("warn: table-postgres: PQexecPrepared: %s",
		    PQerrorMessage(db));
		PQclear(res);
		return (-1);
	}

	source_iter = NULL;
	while(dict_poproot(&sources, NULL, NULL))
		;

	for (i = 0; i < PQntuples(res); i++)
		dict_set(&sources, PQgetvalue(res, i, 0), NULL);

	PQclear(res);

	source_update = time(NULL);
	source_ncall = 0;

    fetch:

	source_ncall += 1;

        if (! dict_iter(&sources, &source_iter, &k, (void **)NULL)) {
		source_iter = NULL;
		if (! dict_iter(&sources, &source_iter, &k, (void **)NULL))
			return (0);
	}

	if (strlcpy(dst, k, sz) >= sz)
		return (-1);

	return (1);
}

