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
static int map_static_config(struct map *, const char *);
static int map_static_update(struct map *, const char *);
static void *map_static_open(struct map *);
static void *map_static_lookup(void *, const char *, enum map_kind);
static int   map_static_compare(void *, const char *, enum map_kind,
    int (*)(const char *, const char *));
static void  map_static_close(void *);

static void *map_static_credentials(const char *, char *, size_t);
static void *map_static_alias(const char *, char *, size_t);
static void *map_static_virtual(const char *, char *, size_t);
static void *map_static_netaddr(const char *, char *, size_t);

struct map_backend map_backend_static = {
	map_static_config,
	map_static_open,
	map_static_update,
	map_static_close,
	map_static_lookup,
	map_static_compare
};

static int
map_static_config(struct map *map, const char *config)
{
	/* no config ? ok */
	if (config == NULL)
		return 1;

	return map_config_parser(map, config); 
}

static int
map_static_update(struct map *map, const char *config)
{
	struct map     *m;
	char		name[MAX_LINE_SIZE];

	/* no config ? ok */
	if (config == NULL)
		goto ok;

	m = map_create(map->m_src, NULL, config);
	if (! m->m_backend->config(m, config))
		goto err;

	/* update successful, swap map names */
	strlcpy(name, map->m_name, sizeof name);
	strlcpy(map->m_name, m->m_name, sizeof map->m_name);
	strlcpy(m->m_name, name, sizeof m->m_name);

	/* swap, map id */
	map->m_id = map->m_id ^ m->m_id;
	m->m_id   = map->m_id ^ m->m_id;
	map->m_id = map->m_id ^ m->m_id;

	/* destroy former map */
	map_destroy(map);

ok:
	log_info("info: Table \"%s\" successfully updated", name);
	return 1;

err:
	map_destroy(m);
	log_info("info: Failed to update table \"%s\"", name);
	return 0;
}

static void *
map_static_open(struct map *map)
{
	return map;
}

static void
map_static_close(void *hdl)
{
	return;
}

static void *
map_static_lookup(void *hdl, const char *key, enum map_kind kind)
{
	struct map	*m  = hdl;
	struct mapel	*me = NULL;
	char		*line;
	void		*ret;
	size_t		 len;

	line = NULL;
	TAILQ_FOREACH(me, &m->m_contents, me_entry) {
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
		ret = map_static_alias(key, line, len);
		break;

	case K_CREDENTIALS:
		ret = map_static_credentials(key, line, len);
		break;

	case K_VIRTUAL:
		ret = map_static_virtual(key, line, len);
		break;

	case K_NETADDR:
		ret = map_static_netaddr(key, line, len);
		break;

	default:
		ret = NULL;
		break;
	}

	free(line);

	return ret;
}

static int
map_static_compare(void *hdl, const char *key, enum map_kind kind,
    int (*func)(const char *, const char *))
{
	struct map	*m   = hdl;
	struct mapel	*me  = NULL;
	int		 ret = 0;

	TAILQ_FOREACH(me, &m->m_contents, me_entry) {
		if (! func(key, me->me_key))
			continue;
		ret = 1;
		break;
	}

	return ret;
}

static void *
map_static_credentials(const char *key, char *line, size_t len)
{
	struct map_credentials *map_credentials = NULL;
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

	map_credentials = xcalloc(1, sizeof *map_credentials,
	    "map_static_credentials");

	if (strlcpy(map_credentials->username, line,
		sizeof(map_credentials->username)) >=
	    sizeof(map_credentials->username))
		goto err;

	if (strlcpy(map_credentials->password, p,
		sizeof(map_credentials->password)) >=
	    sizeof(map_credentials->password))
		goto err;

	return map_credentials;

err:
	free(map_credentials);
	return NULL;
}

static void *
map_static_alias(const char *key, char *line, size_t len)
{
	char	       	*subrcpt;
	char	       	*endp;
	struct map_alias	*map_alias = NULL;
	struct expandnode	 xn;

	map_alias = xcalloc(1, sizeof *map_alias, "map_static_alias");

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

		expand_insert(&map_alias->expand, &xn);
		map_alias->nbnodes++;
	}

	return map_alias;

error:
	expand_free(&map_alias->expand);
	free(map_alias);
	return NULL;
}

static void *
map_static_virtual(const char *key, char *line, size_t len)
{
	char	       	*subrcpt;
	char	       	*endp;
	struct map_virtual	*map_virtual = NULL;
	struct expandnode	 xn;

	map_virtual = xcalloc(1, sizeof *map_virtual, "map_static_virtual");

	/* domain key, discard value */
	if (strchr(key, '@') == NULL)
		return map_virtual;

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

		expand_insert(&map_virtual->expand, &xn);
		map_virtual->nbnodes++;
	}

	return map_virtual;

error:
	expand_free(&map_virtual->expand);
	free(map_virtual);
	return NULL;
}


static void *
map_static_netaddr(const char *key, char *line, size_t len)
{
	struct map_netaddr	*map_netaddr = NULL;

	map_netaddr = xcalloc(1, sizeof *map_netaddr, "map_static_netaddr");

	if (! text_to_netaddr(&map_netaddr->netaddr, line))
	    goto error;

	return map_netaddr;

error:
	free(map_netaddr);
	return NULL;
}
