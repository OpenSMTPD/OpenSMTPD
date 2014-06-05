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

#include <libpq-fe.h>

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

struct config {
	struct dict	 conf;
	PGconn		*db;
	char		*statements[SQL_MAX];
	char		*stmt_fetch_source;
	struct dict	 sources;
	void		*source_iter;
	size_t		 source_refresh;
	size_t		 source_ncall;
	int		 source_expire;
	time_t		 source_update;
};

static int table_postgres_update(void);
static int table_postgres_lookup(int, const char *, char *, size_t);
static int table_postgres_check(int, const char *);
static int table_postgres_fetch(int, char *, size_t);

static PGresult *table_postgres_query(const char *, int);

static struct config 	*config_load(const char *);
static void		 config_reset(struct config *);
static int		 config_connect(struct config *);
static void		 config_free(struct config *);

#define SQL_MAX_RESULT	5

#define	DEFAULT_EXPIRE	60
#define	DEFAULT_REFRESH	1000

static char		*conffile;
static struct config	*config;

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

	conffile = argv[0];

	config = config_load(conffile);
	if (config == NULL) {
		log_warnx("warn: table-postgres: error parsing config file");
		return (1);
	}
	if (config_connect(config) == 0) {
		log_warnx("warn: table-postgres: could not connect");
		return (1);
	}

	table_api_on_update(table_postgres_update);
	table_api_on_check(table_postgres_check);
	table_api_on_lookup(table_postgres_lookup);
	table_api_on_fetch(table_postgres_fetch);
	table_api_dispatch();

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

static struct config *
config_load(const char *path)
{
	struct config	*conf;
	FILE		*fp;
	size_t		 flen;
	char		*key, *value, *buf, *lbuf;
	const char	*e;
	long long	 ll;

	lbuf = NULL;

	conf = calloc(1, sizeof(*conf));
	if (conf == NULL) {
		log_warn("warn: table-postgres: calloc");
		return (NULL);
	}

	dict_init(&conf->conf);
	dict_init(&conf->sources);

	conf->source_refresh = DEFAULT_REFRESH;
	conf->source_expire = DEFAULT_EXPIRE;

	fp = fopen(path, "r");
	if (fp == NULL) {
		log_warn("warn: table-postgres: fopen");
		goto end;
	}

	while ((buf = fgetln(fp, &flen))) {
		if (buf[flen - 1] == '\n')
			buf[flen - 1] = '\0';
		else {
			lbuf = malloc(flen + 1);
			if (lbuf == NULL) {
				log_warn("warn: table-postgres: malloc");
				goto end;
			}
			memcpy(lbuf, buf, flen);
			lbuf[flen] = '\0';
			buf = lbuf;
		}

		key = buf;
		while (isspace((unsigned char)*key))
			++key;
		if (*key == '\0' || *key == '#')
			continue;
		value = key;
		strsep(&value, " \t:");
		if (value) {
			while (*value) {
				if (!isspace((unsigned char)*value) &&
				    !(*value == ':' && isspace((unsigned char)*(value + 1))))
					break;
				++value;
			}
			if (*value == '\0')
				value = NULL;
		}

		if (value == NULL) {
			log_warnx("warn: table-postgres: missing value for key %s", key);
			goto end;
		}

		if (dict_check(&conf->conf, key)) {
			log_warnx("warn: table-postgres: duplicate key %s", key);
			goto end;
		}
		
		value = strdup(value);
		if (value == NULL) {
			log_warn("warn: table-postgres: malloc");
			goto end;
		}

		dict_set(&conf->conf, key, value);
	}

	if ((value = dict_get(&conf->conf, "fetch_source_expire"))) {
		e = NULL;
		ll = strtonum(value, 0, INT_MAX, &e);
		if (e) {
			log_warnx("warn: table-postgres: bad value for fetch_source_expire: %s", e);
			goto end;
		}
		conf->source_expire = ll;
	}
	if ((value = dict_get(&conf->conf, "fetch_source_refresh"))) {
		e = NULL;
		ll = strtonum(value, 0, INT_MAX, &e);
		if (e) {
			log_warnx("warn: table-postgres: bad value for fetch_source_refresh: %s", e);
			goto end;
		}
		conf->source_refresh = ll;
	}

	free(lbuf);
	fclose(fp);
	return (conf);

    end:
	free(lbuf);
	if (fp)
		fclose(fp);
	config_free(conf);
	return (NULL);
}

static void
config_reset(struct config *conf)
{
	size_t	i;

	for (i = 0; i < SQL_MAX; i++)
		if (conf->statements[i]) {
			free(conf->statements[i]);
			conf->statements[i] = NULL;
		}
	if (conf->stmt_fetch_source) {
		free(conf->stmt_fetch_source);
		conf->stmt_fetch_source = NULL;
	}
	if (conf->db) {
		PQfinish(conf->db);
		conf->db = NULL;
	}
}

static int
config_connect(struct config *conf)
{
	static const struct {
		const char	*name;
		int		 cols;
	} qspec[SQL_MAX] = {
		{ "query_alias",	1 },
		{ "query_domain",	1 },
		{ "query_credentials",	2 },
		{ "query_netaddr",	1 },
		{ "query_userinfo",	3 },
		{ "query_source",	1 },
		{ "query_mailaddr",	1 },
		{ "query_addrname",	1 },
	};
	size_t	 i;
	char	*conninfo, *q;

	log_debug("debug: table-postgres: (re)connecting");

	/* Disconnect first, if needed */
	config_reset(conf);

	conninfo = dict_get(&conf->conf, "conninfo");
	if (conninfo == NULL) {
		log_warnx("warn: table-postgres: missing \"conninfo\" configuration directive");
		goto end;
	}

	conf->db = PQconnectdb(conninfo);
	if (conf->db == NULL) {
		log_warnx("warn: table-postgres: PQconnectdb return NULL");
		goto end;
	}
	if (PQstatus(conf->db) != CONNECTION_OK) {
		log_warnx("warn: table-postgres: PQconnectdb: %s",
		    PQerrorMessage(conf->db));
		goto end;
	}

	for (i = 0; i < SQL_MAX; i++) {
		q = dict_get(&conf->conf, qspec[i].name);
		if (q && (conf->statements[i] = table_postgres_prepare_stmt(
		    conf->db, q, 1, qspec[i].cols)) == NULL)
			goto end;
	}

	q = dict_get(&conf->conf, "fetch_source");
	if (q && (conf->stmt_fetch_source = table_postgres_prepare_stmt(conf->db,
	    q, 0, 1)) == NULL)
		goto end;

	log_debug("debug: table-postgres: connected");

	return (1);

    end:
	config_reset(conf);
	return (0);
}

static void
config_free(struct config *conf)
{
	void	*value;

	config_reset(conf);

	while (dict_poproot(&conf->conf, &value))
		free(value);

	while (dict_poproot(&conf->sources, NULL))
		;

	free(conf);
}

static int
table_postgres_update(void)
{
	struct config	*c;

	if ((c = config_load(conffile)) == NULL)
		return (0);
	if (config_connect(c) == 0) {
		config_free(c);
		return (0);
	}

	config_free(config);
	config = c;

	return (1);
}

static PGresult *
table_postgres_query(const char *key, int service)
{
	PGresult	*res;
	const char	*errfld;
	char		*stmt;
	int		 i;

    retry:

	stmt = NULL;
	for(i = 0; i < SQL_MAX; i++)
		if (service == 1 << i) {
			stmt = config->statements[i];
			break;
		}

	if (stmt == NULL)
		return (NULL);

	res = PQexecPrepared(config->db, stmt, 1, &key, NULL, NULL, 0);

	if (PQresultStatus(res) != PGRES_TUPLES_OK) {
		errfld = PQresultErrorField(res, PG_DIAG_SQLSTATE);
		if (errfld[0] == '0' && errfld[1] == '8') {
			log_warnx("warn: table-postgres: trying to reconnect after error: %s",
			    PQerrorMessage(config->db));
			PQclear(res);
			if (config_connect(config))
				goto retry;
			return (NULL);
		}
		log_warnx("warn: table-postgres: PQexecPrepared: %s",
		    PQerrorMessage(config->db));
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

	if (config->db == NULL && config_connect(config) == 0)
		return (-1);

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

	if (config->db == NULL && config_connect(config) == 0)
		return (-1);

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
		memset(dst, 0, sz);
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
		if (snprintf(dst, sz, "%s:%s:%s",
		    PQgetvalue(res, 0, 0),
		    PQgetvalue(res, 0, 1),
		    PQgetvalue(res, 0, 2)) > (ssize_t)sz) {
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
		log_warnx("warn: table-postgres: unknown service %d",
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
	char		*stmt;
	PGresult	*res;
	const char	*k, *errfld;
	int		 i;

	if (config->db == NULL && config_connect(config) == 0)
		return (-1);

    retry:

	if (service != K_SOURCE)
		return (-1);

	stmt = config->stmt_fetch_source;

	if (stmt == NULL)
		return (-1);

	if (config->source_ncall < config->source_refresh &&
	    time(NULL) - config->source_update < config->source_expire)
	    goto fetch;

	res = PQexecPrepared(config->db, stmt, 0, NULL, NULL, NULL, 0);

	if (PQresultStatus(res) != PGRES_TUPLES_OK) {
		errfld = PQresultErrorField(res, PG_DIAG_SQLSTATE);
		if (errfld[0] == '0' && errfld[1] == '8') {
			log_warnx("warn: table-postgres: trying to reconnect after error: %s",
			    PQerrorMessage(config->db));
			PQclear(res);
			if (config_connect(config))
				goto retry;
			return (-1);
		}
		log_warnx("warn: table-postgres: PQexecPrepared: %s",
		    PQerrorMessage(config->db));
		PQclear(res);
		return (-1);
	}

	config->source_iter = NULL;
	while (dict_poproot(&config->sources, NULL))
		;

	for (i = 0; i < PQntuples(res); i++)
		dict_set(&config->sources, PQgetvalue(res, i, 0), NULL);

	PQclear(res);

	config->source_update = time(NULL);
	config->source_ncall = 0;

    fetch:

	config->source_ncall += 1;

	if (! dict_iter(&config->sources, &config->source_iter, &k, (void **)NULL)) {
		config->source_iter = NULL;
		if (! dict_iter(&config->sources, &config->source_iter, &k, (void **)NULL))
			return (0);
	}

	if (strlcpy(dst, k, sz) >= sz)
		return (-1);

	return (1);
}
