/*	$OpenBSD: aliases.c,v 1.58 2012/11/12 14:58:53 eric Exp $	*/

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
#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <util.h>

#include "smtpd.h"
#include "log.h"

static int aliases_expand_include(struct expand *, const char *);
static int alias_is_filter(struct expandnode *, const char *, size_t);
static int alias_is_username(struct expandnode *, const char *, size_t);
static int alias_is_address(struct expandnode *, const char *, size_t);
static int alias_is_filename(struct expandnode *, const char *, size_t);
static int alias_is_include(struct expandnode *, const char *, size_t);

int
aliases_get(struct table *table, struct expand *expand, const char *username)
{
	struct table_alias     *table_alias = NULL;
	struct expandnode      *xn;
	char			buf[MAX_LOCALPART_SIZE];
	size_t			nbaliases;
	int			ret;

	
	xlowercase(buf, username, sizeof(buf));
	ret = table_lookup(table, buf, K_ALIAS, (void **)&table_alias);
	if (ret <= 0)
		return ret;

	/* foreach node in table_alias expandtree, we merge */
	nbaliases = 0;
	RB_FOREACH(xn, expandtree, &table_alias->expand.tree) {
		if (xn->type == EXPAND_INCLUDE)
			nbaliases += aliases_expand_include(expand,
			    xn->u.buffer);
		else {
			expand_insert(expand, xn);
			nbaliases++;
		}
	}

	expand_free(&table_alias->expand);
	free(table_alias);

	log_debug("debug: aliases_get: returned %zd aliases", nbaliases);
	return nbaliases;
}

int
aliases_virtual_check(struct table *table, const struct mailaddr *maddr)
{
	char			buf[MAX_LINE_SIZE];
	char		       *pbuf;
	int			ret;

	if (! bsnprintf(buf, sizeof(buf), "%s@%s", maddr->user,
		maddr->domain))
		return 0;	
	xlowercase(buf, buf, sizeof(buf));

	/* First, we lookup for full entry: user@domain */
	ret = table_lookup(table, buf, K_ALIAS, NULL);
	if (ret < 0)
		return (-1);
	if (ret)
		return 1;

	/* Failed ? We lookup for username only */
	pbuf = strchr(buf, '@');
	*pbuf = '\0';
	ret = table_lookup(table, buf, K_ALIAS, NULL);
	if (ret < 0)
		return (-1);
	if (ret)
		return 1;

	*pbuf = '@';
	/* Failed ? We lookup for catch all for virtual domain */
	ret = table_lookup(table, pbuf, K_ALIAS, NULL);
	if (ret < 0)
		return (-1);
	if (ret)
		return 1;

	/* Failed ? We lookup for a *global* catch all */
	ret = table_lookup(table, "@", K_ALIAS, NULL);
	if (ret <= 0)
		return (ret);

	return 1;
}

int
aliases_virtual_get(struct table *table, struct expand *expand,
    const struct mailaddr *maddr)
{
	struct table_alias     *table_alias = NULL;
	struct expandnode      *xn;
	char			buf[MAX_LINE_SIZE];
	char		       *pbuf;
	int			nbaliases;
	int			ret;

	if (! bsnprintf(buf, sizeof(buf), "%s@%s", maddr->user,
		maddr->domain))
		return 0;	
	xlowercase(buf, buf, sizeof(buf));

	/* First, we lookup for full entry: user@domain */
	ret = table_lookup(table, buf, K_ALIAS, (void **)&table_alias);
	if (ret < 0)
		return (-1);
	if (ret)
		goto expand;

	/* Failed ? We lookup for username only */
	pbuf = strchr(buf, '@');
	*pbuf = '\0';
	ret = table_lookup(table, buf, K_ALIAS, (void **)&table_alias);
	if (ret < 0)
		return (-1);
	if (ret)
		goto expand;

	*pbuf = '@';
	/* Failed ? We lookup for catch all for virtual domain */
	ret = table_lookup(table, pbuf, K_ALIAS, (void **)&table_alias);
	if (ret < 0)
		return (-1);
	if (ret)
		goto expand;

	/* Failed ? We lookup for a *global* catch all */
	ret = table_lookup(table, "@", K_ALIAS, (void **)&table_alias);
	if (ret <= 0)
		return (ret);

expand:
	/* foreach node in table_virtual expand, we merge */
	nbaliases = 0;
	RB_FOREACH(xn, expandtree, &table_alias->expand.tree) {
		if (xn->type == EXPAND_INCLUDE)
			nbaliases += aliases_expand_include(expand,
			    xn->u.buffer);
		else {
			expand_insert(expand, xn);
			nbaliases++;
		}
	}

	expand_free(&table_alias->expand);
	free(table_alias);
	log_debug("debug: aliases_virtual_get: '%s' resolved to %d nodes",
	    buf, nbaliases);

	return nbaliases;
}

static int
aliases_expand_include(struct expand *expand, const char *filename)
{
	FILE *fp;
	char *line;
	size_t len;
	size_t lineno = 0;
	char delim[] = { '\\', '#' };
	struct expandnode xn;

	fp = fopen(filename, "r");
	if (fp == NULL) {
		log_warn("warn: failed to open include file \"%s\".", filename);
		return 0;
	}

	while ((line = fparseln(fp, &len, &lineno, delim, 0)) != NULL) {
		if (len == 0) {
			free(line);
			continue;
		}

		if (! alias_parse(&xn, line))
			log_warnx("warn: could not parse include entry \"%s\".",
			    line);

		if (xn.type == EXPAND_INCLUDE)
			log_warnx("warn: nested inclusion is not supported.");
		else
			expand_insert(expand, &xn);

		free(line);
	}

	fclose(fp);
	return 1;
}

int
alias_parse(struct expandnode *alias, char *line)
{
	size_t l;
	char *wsp;

	/* remove ending whitespaces */
	wsp = line + strlen(line);
	while (wsp != line) {
		if (*wsp != '\0' && !isspace((int)*wsp))
			break;
		*wsp-- = '\0';
	}

	l = strlen(line);
	if (alias_is_include(alias, line, l) ||
	    alias_is_filter(alias, line, l) ||
	    alias_is_filename(alias, line, l) ||
	    alias_is_address(alias, line, l) ||
	    alias_is_username(alias, line, l))
		return (1);

	return (0);
}


static int
alias_is_filter(struct expandnode *alias, const char *line, size_t len)
{
	if (*line == '|') {
		if (strlcpy(alias->u.buffer, line + 1,
			sizeof(alias->u.buffer)) >= sizeof(alias->u.buffer))
			return 0;
		alias->type = EXPAND_FILTER;
		return 1;
	}
	return 0;
}

static int
alias_is_username(struct expandnode *alias, const char *line, size_t len)
{
	bzero(alias, sizeof *alias);

	if (strlcpy(alias->u.user, line,
	    sizeof(alias->u.user)) >= sizeof(alias->u.user))
		return 0;

	while (*line) {
		if (!isalnum((int)*line) &&
		    *line != '_' && *line != '.' && *line != '-')
			return 0;
		++line;
	}

	alias->type = EXPAND_USERNAME;
	return 1;
}

static int
alias_is_address(struct expandnode *alias, const char *line, size_t len)
{
	char *domain;

	bzero(alias, sizeof *alias);

	if (len < 3)	/* x@y */
		return 0;

	domain = strchr(line, '@');
	if (domain == NULL)
		return 0;

	/* @ cannot start or end an address */
	if (domain == line || domain == line + len - 1)
		return 0;

	/* scan pre @ for disallowed chars */
	*domain++ = '\0';
	strlcpy(alias->u.mailaddr.user, line, sizeof(alias->u.mailaddr.user));
	strlcpy(alias->u.mailaddr.domain, domain,
	    sizeof(alias->u.mailaddr.domain));

	while (*line) {
		char allowedset[] = "!#$%*/?|^{}`~&'+-=_.";
		if (!isalnum((int)*line) &&
		    strchr(allowedset, *line) == NULL)
			return 0;
		++line;
	}

	while (*domain) {
		char allowedset[] = "-.";
		if (!isalnum((int)*domain) &&
		    strchr(allowedset, *domain) == NULL)
			return 0;
		++domain;
	}

	alias->type = EXPAND_ADDRESS;
	return 1;
}

static int
alias_is_filename(struct expandnode *alias, const char *line, size_t len)
{
	bzero(alias, sizeof *alias);

	if (*line != '/')
		return 0;

	if (strlcpy(alias->u.buffer, line,
	    sizeof(alias->u.buffer)) >= sizeof(alias->u.buffer))
		return 0;
	alias->type = EXPAND_FILENAME;
	return 1;
}

static int
alias_is_include(struct expandnode *alias, const char *line, size_t len)
{
	size_t skip;

	bzero(alias, sizeof *alias);

	if (strncasecmp(":include:", line, 9) == 0)
		skip = 9;
	else if (strncasecmp("include:", line, 8) == 0)
		skip = 8;
	else
		return 0;

	if (! alias_is_filename(alias, line + skip, len - skip))
		return 0;

	alias->type = EXPAND_INCLUDE;
	return 1;
}
