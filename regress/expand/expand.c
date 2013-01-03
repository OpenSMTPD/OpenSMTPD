/*	$OpenBSD: expand.c,v 1.18 2012/10/10 18:02:37 eric Exp $	*/

/*
 * Copyright (c) 2009 Gilles Chehade <gilles@poolp.org>
 * Copyright (c) 2012 Eric Faurot <eric@openbsd.org>
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

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <util.h>

#define MAX_LINE_SIZE	2048

static char *
strip(char *s)
{
	size_t	 l;

	while (*s == ' ' || *s == '\t')
		s++;

	for (l = strlen(s); l; l--) {
		if (s[l-1] != ' ' && s[l-1] != '\t')
			break;
		s[l-1] = '\0';
	}

	return (s);
}

static int
expand_line_split(char **line, char **ret)
{
	static char	buffer[MAX_LINE_SIZE];
	int		esc, i, dq, sq;
	char	       *s;

	bzero(buffer, sizeof buffer);
	esc = dq = sq = i = 0;
	for (s = *line; (*s) && (i < (int)sizeof(buffer)); ++s) {
		if (esc) {
			buffer[i++] = *s;
			esc = 0;
			continue;
		}
		if (*s == '\\') {
			esc = 1;
			continue;
		}
		if (*s == ',' && !dq && !sq) {
			*ret = buffer;
			*line = s+1;
			return (1);
		}

		buffer[i++] = *s;
		esc = 0;

		if (*s == '"' && !sq)
			dq ^= 1;
		if (*s == '\'' && !dq)
			sq ^= 1;
	}

	if (esc || dq || sq || i == sizeof(buffer))
		return (-1);

	*ret = buffer;
	*line = s;
	return (i ? 1 : 0);
}

int
expand_line(const char *s)
{
	char		buffer[MAX_LINE_SIZE];
	char		*p, *subrcpt;
	int		ret;

	bzero(buffer, sizeof buffer);
	if (strlcpy(buffer, s, sizeof buffer) >= sizeof buffer)
		return 0;

	p = buffer;
	while ((ret = expand_line_split(&p, &subrcpt)) > 0) {
		printf("   -> [%s]", subrcpt);
		printf(" (%s)\n", strip(subrcpt));
	}

	if (ret >= 0)
		return 1;
	return 0;
}

int
main(int argc, char **argv)
{
	FILE	*fp;
	char	*line;
	size_t	len;
	size_t	lineno;

	fp = fopen(argv[1], "r");
	if (fp == NULL)
		err(1, "fopen");

	while ((line = fparseln(fp, &len, &lineno, NULL, 0)) != NULL) {
		printf("=> [%s]\n", line);
		if (! expand_line(line))
			printf("error!\n");
		free(line);
	}

	return (0);
}
