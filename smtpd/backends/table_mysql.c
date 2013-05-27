/*	$OpenBSD: table_mysql.c,v 1.2 2013/01/31 18:34:43 eric Exp $	*/

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

#include <sys/types.h>

#include <ctype.h>
#include <fcntl.h>
#include <mysql/mysql.h>
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

static int table_mysql_update(void);
static int table_mysql_lookup(int, const char *, char *, size_t);
static int table_mysql_check(int, const char *);
static int table_mysql_fetch(int, char *, size_t);

static MYSQL_STMT *table_mysql_query(const char *, int);

static char		*config;
static MYSQL		*db;
static MYSQL_STMT	*statements[SQL_MAX];

#define SQL_MAX_RESULT	5

static MYSQL_BIND	results[SQL_MAX_RESULT];
static char		results_buffer[SQL_MAX_RESULT][SMTPD_MAXLINESIZE];

int
main(int argc, char **argv)
{
	int	ch, i;

	log_init(1);

	config = NULL;

	while ((ch = getopt(argc, argv, "f:")) != -1) {
		switch (ch) {
		case 'f':
			config = optarg;
			break;
		default:
			log_warnx("warn: backend-table-mysql: bad option");
			return (1);
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;

	if (config == NULL) {
		log_warnx("warn: backend-table-mysql: config file not specified");
		return (1);
	}

	if (argc != 0) {
		log_warnx("warn: backend-table-mysql: bogus argument(s)");
		return (1);
	}

	for (i = 0; i < SQL_MAX_RESULT; i++) {
		results[i].buffer_type = MYSQL_TYPE_STRING;
		results[i].buffer = results_buffer[i];
		results[i].buffer_length = SMTPD_MAXLINESIZE;
		results[i].is_null = 0;
	}

	if (table_mysql_update() == 0) {
		log_warnx("warn: backend-table-mysql: error parsing config file");
		return (1);
	}

	table_api_on_update(table_mysql_update);
	table_api_on_check(table_mysql_check);
	table_api_on_lookup(table_mysql_lookup);
	table_api_on_fetch(table_mysql_fetch);
	table_api_dispatch();

	return (0);
}

static int
table_mysql_getconfstr(const char *key, const char *value, char **var)
{
	if (*var) {
		log_warnx("warn: backend-table-mysql: duplicate %s %s", key, value);
		free(*var);
	}
	*var = strdup(value);
	if (*var == NULL) {
		log_warn("warn: backend-table-mysql: strdup");
		return (-1);
	}
	return (0);
}

static int
table_mysql_update(void)
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
	MYSQL		*_db;
	MYSQL_STMT	*_statements[SQL_MAX];
	MYSQL_RES	*metadata;
	char		*queries[SQL_MAX];
	size_t		 flen;
	FILE		*fp;
	char		*key, *value, *buf, *lbuf;
	char		*host, *username, *password, *database;
	int		 i, ret, count;

	host = NULL;
	username = NULL;
	password = NULL;
	database = NULL;
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
				log_warn("warn: backend-table-mysql: malloc");
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
			log_warnx("warn: backend-table-mysql: missing value for key %s", key);
			continue;
		}

		if (!strcmp("host", key)) {
			if (table_mysql_getconfstr(key, value, &host) == -1)
				goto end;
			continue;
		}
		if (!strcmp("username", key)) {
			if (table_mysql_getconfstr(key, value, &username) == -1)
				goto end;
			continue;
		}
		if (!strcmp("password", key)) {
			if (table_mysql_getconfstr(key, value, &password) == -1)
				goto end;
			continue;
		}
		if (!strcmp("database", key)) {
			if (table_mysql_getconfstr(key, value, &database) == -1)
				goto end;
			continue;
		}

		for(i = 0; i < SQL_MAX; i++)
			if (!strcmp(qspec[i].name, key))
				break;
		if (i == SQL_MAX) {
			log_warnx("warn: backend-table-mysql: bogus key %s", key);
			continue;
		}

		if (queries[i]) {
			log_warnx("warn: backend-table-mysql: duplicate key %s", key);
			continue;
		}

		queries[i] = strdup(value);
		if (queries[i] == NULL) {
			log_warnx("warn: backend-table-mysql: strdup");
			goto end;
		}
	}

	/* Setup db */

	log_debug("debug: backend-table-mysql: opening mysql://%s@%s/%s",
	    username, host, database);

	_db = mysql_init(NULL);
	if (_db == NULL) {
		log_warnx("warn: backend-table-mysql: mysql_init() failed");
		goto end;
	}

	if (mysql_real_connect(_db, host, username, password, database, 0, NULL, 0)) {
		log_warnx("warn: backend-table-mysql: could not connect");
		goto end;
	}

	for (i = 0; i < SQL_MAX; i++) {
		if (queries[i] == NULL)
			continue;
		if ((_statements[i] = mysql_stmt_init(_db)) == NULL) {
			log_warnx("warn: backend-table-mysql: mysql_stmt_init() failed");
			goto end;
		}
		if (mysql_stmt_prepare(_statements[i], queries[i], strlen(queries[i]))) {
			log_warnx("warn: backend-table-mysql: mysql_stmt_init() failed");
			goto end;
		}
		if (mysql_stmt_param_count(_statements[i]) != 1) {
			log_warnx("warn: backend-table-mysql: columns: invalid query");
			goto end;
		}
		metadata = mysql_stmt_result_metadata(_statements[i]);
		if (metadata == NULL) {
			log_warnx("warn: backend-table-mysql: mysql_stmt_result_metadata() failed");
			goto end;
		}
		count = mysql_num_fields(metadata);
		mysql_free_result(metadata);
		if (count != qspec[i].cols) {
			log_warnx("warn: backend-table-mysql: invalid number of columns in resultset");
			goto end;
		}
		if (mysql_stmt_bind_result(_statements[i], results)) {
			log_warnx("warn: backend-table-mysql: mysql_stmt_bind_results() failed");
			goto end;
		}
	}

	/* Replace previous setup */

	for (i = 0; i < SQL_MAX; i++) {
		if (statements[i])
			mysql_stmt_close(statements[i]);
		statements[i] = _statements[i];
		_statements[i] = NULL;
	}
	if (db)
		mysql_close(_db);
	db = _db;
	_db = NULL;

	log_debug("debug: backend-table-mysql: config successfully updated");
	ret = 1;

    end:

	/* Cleanup */
	for (i = 0; i < SQL_MAX; i++) {
		if (_statements[i])
			mysql_stmt_close(_statements[i]);
		free(queries[i]);
	}
	if (_db)
		mysql_close(_db);

	free(host);
	free(username);
	free(password);
	free(database);

	free(lbuf);
	fclose(fp);
	return (ret);
}

static MYSQL_STMT *
table_mysql_query(const char *key, int service)
{
	MYSQL_STMT	*stmt;
	MYSQL_BIND	 param[1];
	unsigned long	 keylen;
	char		 buffer[SMTPD_MAXLINESIZE];
	int		 i;

	stmt = NULL;
	for(i = 0; i < SQL_MAX; i++)
		if (service == 1 << i) {
			stmt = statements[i];
			break;
		}

	if (stmt == NULL)
		return (NULL);

	if (strlcpy(buffer, key, sizeof(buffer)) >= sizeof(buffer)) {
		log_warnx("warn: backend-table-mysql: key too long: \"%s\"", key);
		return (NULL);
	}

	keylen = strlen(key);

	param[0].buffer_type = MYSQL_TYPE_STRING;
	param[0].buffer = buffer;
	param[0].buffer_length = sizeof(buffer);
	param[0].is_null = 0;
	param[0].length = &keylen;

	if (mysql_stmt_bind_param(stmt, param)) {
		log_warnx("warn: backend-table-mysql: mysql_stmt_bind_param() failed");
		return (NULL);
	}

	if (mysql_stmt_execute(stmt)) {
		log_warnx("warn: backend-table-mysql: mysql_stmt_execute() failed");
		return (NULL);
	}

	return (stmt);
}

static int
table_mysql_check(int service, const char *key)
{
	MYSQL_STMT		*stmt;
	unsigned long long	r;

	stmt = table_mysql_query(key, service);
	if (stmt == NULL)
		return (-1);

	r = mysql_stmt_fetch(stmt);
	if (mysql_stmt_free_result(stmt)) {
		log_warnx("warn: backend-table-mysql: mysql_stmt_free_result() failed");
		return (-1);
	}

	if (r == 0)
		return (1);

	if (r == MYSQL_NO_DATA)
		return (0);

	log_warnx("warn: backend-table-mysql: mysql_stmt_fetch() failed with %llu", r);

	return (-1);
}

static int
table_mysql_lookup(int service, const char *key, char *dst, size_t sz)
{
	MYSQL_STMT		*stmt;
	unsigned long long	 s;
	int			 r;

	stmt = table_mysql_query(key, service);
	if (stmt == NULL)
		return (-1);

	s = mysql_stmt_fetch(stmt);
	if (s == MYSQL_NO_DATA) {
		r = 0;
		goto end;
	}
	
	if (s != 0) {
		r = -1;
		goto end;
	}

	r = 1;

	switch(service) {
	case K_ALIAS:
		do {
			if (dst[0] && strlcat(dst, ", ", sz) >= sz) {
				r = -1;
				break;
			}
			if (strlcat(dst, results_buffer[0], sz) >= sz) {
				r = -1;
				break;
			}
			s = mysql_stmt_fetch(stmt);
		} while (s == 0);

		if (s != MYSQL_NO_DATA)
			r = -1;
		break;
	case K_CREDENTIALS:
		if (snprintf(dst, sz, "%s:%s",
		    results_buffer[0],
		    results_buffer[1]) > (ssize_t)sz)
			r = -1;
		break;
	case K_USERINFO:
		if (snprintf(dst, sz, "%s:%s:%s:%s",
		    results_buffer[0],
		    results_buffer[1],
		    results_buffer[2],
		    results_buffer[3]) > (ssize_t)sz)
			r = -1;
		break;
	case K_DOMAIN:
	case K_NETADDR:
	case K_SOURCE:
	case K_MAILADDR:
	case K_ADDRNAME:
		if (strlcpy(dst, results_buffer[0], sz) >= sz)
			r = -1;
		break;
	default:
		r = -1;
	}

    end:
	

	return (r);
}

static int
table_mysql_fetch(int service, char *dst, size_t sz)
{
	return (-1);
}
