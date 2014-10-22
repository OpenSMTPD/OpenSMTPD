/*	$OpenBSD: rfc822.c,v 1.4 2014/10/15 08:04:41 gilles Exp $	*/

/*
 * Copyright (c) 2014 Gilles Chehade <gilles@poolp.org>
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
#include <sys/queue.h>
#include <sys/tree.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "rfc822.h"

#include "log.h"

static int
parse_addresses_finish(struct rfc822_parser *rp)
{
	char			*wptr;

	/* some flags still set, malformed header */
	if (rp->escape || rp->comment || rp->quote || rp->bracket) {
		free(rp->ra);
		return 0;
	}

	/* no value, malformed header */
	if (rp->ra->name[0] == '\0' && rp->ra->address[0] == '\0') {
		free(rp->ra);
		return 0;
	}

	/* no <>, use name as address */
	if (rp->ra->address[0] == '\0') {
		memcpy(rp->ra->address, rp->ra->name, sizeof rp->ra->address);
		memset(rp->ra->name, 0, sizeof rp->ra->name);
	}

	/* strip first trailing whitespace from name */
	wptr = &rp->ra->name[0] + strlen(rp->ra->name);
	while (wptr != &rp->ra->name[0]) {
		if (*wptr && ! isspace(*wptr))
			break;
		*wptr-- = '\0';
	}

	log_debug("rfc822: address: %s", rp->ra->address);
	log_debug("rfc822: name: %s", rp->ra->name);

	TAILQ_INSERT_TAIL(&rp->addresses, rp->ra, next);
	rp->count++;
	rp->ra = NULL;

	return 1;
}

static int
parse_addresses(struct rfc822_parser *rp, const char *buffer, size_t len)
{
	const char		*s;
	char			*wptr;

	s = buffer;

	/* skip over whitespaces */
	for (s = buffer; *s && isspace(*s); ++s, len--)
		;

	/* we should now pointing to the beginning of a recipient */
	if (*s == '\0')
		return 0;

	if (rp->ra == NULL) {
		rp->ra = calloc(1, sizeof *(rp->ra));
		if (rp->ra == NULL)
			return -1;
	}
	else {
		log_debug("rfc822: reuse: addr = '%s' name = '%s'", rp->ra->address, rp->ra->name);
	}

	wptr = rp->ra->name;
	for (; len; s++, len--) {
		if (*s == '(' && !rp->escape && !rp->quote)
			rp->comment++;
		if (*s == '"' && !rp->escape && !rp->comment)
			rp->quote = !rp->quote;
		if (!rp->comment && !rp->quote && !rp->escape) {
			if (*s == '<' && rp->bracket) {
				free(rp->ra);
				return 0;
			}
			if (*s == '>' && !rp->bracket) {
				free(rp->ra);
				return 0;
			}

			if (*s == '<') {
				wptr = rp->ra->address;
				rp->bracket++;
				continue;
			}
			if (*s == '>') {
				rp->bracket--;
				continue;
			}
			if (*s == ',' || *s == ';')
				break;
		}
		if (*s == ')' && !rp->escape && !rp->quote && rp->comment)
			rp->comment--;
		if (*s == '\\' && !rp->escape && !rp->comment && !rp->quote)
			rp->escape = 1;
		else
			rp->escape = 0;
		*wptr++ = *s;
	}

	if (*s == '\0')
		return 1;

	if (!parse_addresses_finish(rp))
		return 0;

	/* do we have more to process ? */
	for (; *s; ++s, --len)
		if (*s == ',' || *s == ';')
			break;

	/* nope, we're done */
	if (*s == '\0')
		return 1;

	/* there's more to come */
	if (*s == ',' || *s == ';') {
		s++;
		len--;
	}
	if (len)
		return parse_addresses(rp, s, len);
	return 1;
}

void
rfc822_parser_init(struct rfc822_parser *rp)
{
	memset(rp, 0, sizeof *rp);
	TAILQ_INIT(&rp->addresses);
}

void
rfc822_parser_reset(struct rfc822_parser *rp)
{
	struct rfc822_address	*ra;

	while ((ra = TAILQ_FIRST(&rp->addresses))) {
		TAILQ_REMOVE(&rp->addresses, ra, next);
		free(ra);
	}
	memset(rp, 0, sizeof *rp);
}

void
rfc822_parser_finish(struct rfc822_parser *rp)
{
	if (!rp->ra)
		return;

	parse_addresses_finish(rp);
}

int
rfc822_parser_feed(struct rfc822_parser *rp, const char *line)
{
	if (rp->count >= RFC822_MAX_BUFFERS)
		return -1;
	return parse_addresses(rp, line, strlen(line));
}
