/*	$OpenBSD: map.c,v 1.35 2012/11/12 14:58:53 eric Exp $	*/

/*
 * Copyright (c) 2008 Gilles Chehade <gilles@openbsd.org>
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
#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "smtpd.h"
#include "log.h"

struct table_backend *map_backend_lookup(const char *);

extern struct table_backend map_backend_static;
extern struct table_backend map_backend_db;

static objid_t	last_map_id = 0;

struct table_backend *
map_backend_lookup(const char *source)
{
	if (!strcmp(source, "static") || !strcmp(source, "file"))
		return &map_backend_static;
	if (!strcmp(source, "db"))
		return &map_backend_db;
	return NULL;
}

struct table *
map_findbyname(const char *name)
{
	struct table	*m;

	TAILQ_FOREACH(m, env->sc_tables, m_entry) {
		if (strcmp(m->m_name, name) == 0)
			break;
	}
	return (m);
}

struct table *
map_find(objid_t id)
{
	struct table	*m;

	TAILQ_FOREACH(m, env->sc_tables, m_entry) {
		if (m->m_id == id)
			break;
	}
	return (m);
}

void *
map_lookup(objid_t mapid, const char *key, enum table_kind kind)
{
	void *hdl = NULL;
	char *ret = NULL;
	struct table *map;
	struct table_backend *backend = NULL;

	map = map_find(mapid);
	if (map == NULL) {
		errno = EINVAL;
		return NULL;
	}

	backend = map_backend_lookup(map->m_src);
	hdl = backend->open(map);
	if (hdl == NULL) {
		log_warn("warn: map_lookup: can't open %s", map->m_config);
		if (errno == 0)
			errno = ENOTSUP;
		return NULL;
	}

	ret = backend->lookup(hdl, key, kind);

	backend->close(hdl);
	errno = 0;
	return ret;
}

int
map_compare(objid_t mapid, const char *key, enum table_kind kind,
    int (*func)(const char *, const char *))
{
	void *hdl = NULL;
	struct table *map;
	struct table_backend *backend = NULL;
	int ret;

	map = map_find(mapid);
	if (map == NULL) {
		errno = EINVAL;
		return 0;
	}

	backend = map_backend_lookup(map->m_src);
	hdl = backend->open(map);
	if (hdl == NULL) {
		log_warn("warn: map_compare: can't open %s", map->m_config);
		if (errno == 0)
			errno = ENOTSUP;
		return 0;
	}

	ret = backend->compare(hdl, key, kind, func);

	backend->close(hdl);
	errno = 0;
	return ret;	
}

struct table *
map_create(const char *source, const char *name, const char *config)
{
	struct table		*m;
	struct table_backend	*mb;
	size_t		 n;

	if (name && map_findbyname(name))
		errx(1, "map_create: map \"%s\" already defined", name);

	if ((mb = map_backend_lookup(source)) == NULL)
		errx(1, "map_create: backend \"%s\" does not exist", source);

	m = xcalloc(1, sizeof(*m), "map_create");
	m->m_backend = mb;

	if (strlcpy(m->m_src, source, sizeof m->m_src) >= sizeof m->m_src)
		errx(1, "map_create: map source \"%s\" too large", m->m_src);

	if (config && *config) {
		if (strlcpy(m->m_config, config, sizeof m->m_config)
		    >= sizeof m->m_config)
			errx(1, "map_create: map config \"%s\" too large", m->m_config);
	}

	if (strcmp(m->m_src, "static") != 0)
		m->m_type = T_DYNAMIC;

	m->m_id = ++last_map_id;
	if (m->m_id == INT_MAX)
		errx(1, "map_create: too many maps defined");

	if (name == NULL)
		snprintf(m->m_name, sizeof(m->m_name), "<dynamic:%u>", m->m_id);
	else {
		n = strlcpy(m->m_name, name, sizeof(m->m_name));
		if (n >= sizeof(m->m_name))
			errx(1, "map_create: map name too long");
	}

	TAILQ_INIT(&m->m_contents);
	TAILQ_INSERT_TAIL(env->sc_tables, m, m_entry);

	return (m);
}

void
map_destroy(struct table *m)
{
	struct mapel	*me;

	if (strcmp(m->m_src, "static") != 0)
		errx(1, "map_add: cannot delete all from map");

	while ((me = TAILQ_FIRST(&m->m_contents))) {
		TAILQ_REMOVE(&m->m_contents, me, me_entry);
		free(me);
	}

	TAILQ_REMOVE(env->sc_tables, m, m_entry);
	free(m);
}

void
map_add(struct table *m, const char *key, const char *val)
{
	struct mapel	*me;
	size_t		 n;

	if (strcmp(m->m_src, "static") != 0)
		errx(1, "map_add: cannot add to map");

	me = xcalloc(1, sizeof(*me), "map_add");
	n = strlcpy(me->me_key, key, sizeof(me->me_key));
	if (n >= sizeof(me->me_key))
		errx(1, "map_add: key too long");

	if (val) {
		n = strlcpy(me->me_val, val,
		    sizeof(me->me_val));
		if (n >= sizeof(me->me_val))
			errx(1, "map_add: value too long");
	}

	TAILQ_INSERT_TAIL(&m->m_contents, me, me_entry);
}

void
map_delete(struct table *m, const char *key)
{
	struct mapel	*me;
	
	if (strcmp(m->m_src, "static") != 0)
		errx(1, "map_add: cannot delete from map");

	TAILQ_FOREACH(me, &m->m_contents, me_entry) {
		if (strcmp(me->me_key, key) == 0)
			break;
	}
	if (me == NULL)
		return;
	TAILQ_REMOVE(&m->m_contents, me, me_entry);
	free(me);
}

void *
map_open(struct table *m)
{
	struct table_backend *backend = NULL;

	backend = map_backend_lookup(m->m_src);
	if (backend == NULL)
		return NULL;
	return backend->open(m);
}

void
map_close(struct table *m, void *hdl)
{
	struct table_backend *backend = NULL;

	backend = map_backend_lookup(m->m_src);
	backend->close(hdl);
}


void
map_update(struct table *m)
{
	struct table_backend *backend = NULL;

	backend = map_backend_lookup(m->m_src);
	backend->update(m, m->m_config[0] ? m->m_config : NULL);
}

int
map_config_parser(struct table *m, const char *config)
{
	FILE	*fp;
	char *buf, *lbuf;
	size_t flen;
	char *keyp;
	char *valp;
	size_t	ret = 0;

	if (strcmp("static", m->m_src) != 0) {
		log_warn("map_config_parser: configuration map must be static");
		return 0;
	}

	fp = fopen(config, "r");
	if (fp == NULL)
		return 0;

	lbuf = NULL;
	while ((buf = fgetln(fp, &flen))) {
		if (buf[flen - 1] == '\n')
			buf[flen - 1] = '\0';
		else {
			lbuf = xmalloc(flen + 1, "map_stdio_get_entry");
			memcpy(lbuf, buf, flen);
			lbuf[flen] = '\0';
			buf = lbuf;
		}
		
		keyp = buf;
		while (isspace((int)*keyp))
			++keyp;
		if (*keyp == '\0' || *keyp == '#')
			continue;		
		valp = keyp;
		strsep(&valp, " \t:");
		if (valp) {
			while (*valp && isspace(*valp))
				++valp;
			if (*valp == '\0')
				valp = NULL;
		}

		/**/
		if (m->m_type == 0)
			m->m_type = (valp == keyp) ? T_LIST : T_HASH;

		if ((valp == keyp || valp == NULL) && m->m_type == T_LIST)
			map_add(m, keyp, NULL);
		else if ((valp != keyp && valp != NULL) && m->m_type == T_HASH)
			map_add(m, keyp, valp);
		else
			goto end;
	}
	ret = 1;
end:
	free(lbuf);
	fclose(fp);
	return ret;
}
