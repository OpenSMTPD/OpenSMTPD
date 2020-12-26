/*
 * Copyright (c) 2013 Sunil Nimmagadda <sunil@sunilnimmagadda.com>
 * Copyright (c) 2013 Gilles Chehade <gilles@poolp.org>
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

#ifdef HAVE_CRYPT_H
#include <crypt.h> /* needed for crypt() */
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef CRYPT_GENSALT_IMPLEMENTS_DEFAULT_PREFIX
#define PASSWORD_LEN	128
#endif
#define SALT_LEN	16

struct hashing_method {
	char           *prefix;
	unsigned long	count;
};

static unsigned char itoa64[] =	 /* 0 ... 63 => ascii - 64 */
	"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
static struct hashing_method ids[] = {
	{"$y$", 8},
	{"$gy$", 8},
	{"$7$", 10},
	{"$2a$", 10},
	{"$2b$", 10},
	{"$2y$", 10},
	{"$6$", 10000},
	{"$5$", 10000},
	{"$3$", 1},
	{"$2$", 10},
	{"$1$", 1000}
};

static void to64(char *, long int, int);
static void print_passwd(const char *);

int
main(int argc, char *argv[])
{
	char *line;
	size_t linesz;
	ssize_t linelen;

	if (argc > 2) {
		fprintf(stderr, "usage: encrypt <string>\n");
		return (1);
	}

	if (argc == 2) {
		print_passwd(argv[1]);
		return (0);
	}

	line = NULL;
	linesz = 0;
	while ((linelen = getline(&line, &linesz, stdin)) != -1) {
		if (line[linelen - 1] == '\n')
			line[linelen - 1] = '\0';
		print_passwd(line);
	}
	free(line);

	return (0);
}

void
print_passwd(const char *string)
{
	const char     *id;
	char		salt[SALT_LEN+1];
#ifndef CRYPT_GENSALT_IMPLEMENTS_DEFAULT_PREFIX
	char		buffer[PASSWORD_LEN];
#else
	char           *buffer;
#endif
	int		n;
	const char     *p;
	int		nb_ids = sizeof(ids) / sizeof(ids[0]);

	for (n = 0; n < SALT_LEN; ++n)
		to64(&salt[n], arc4random_uniform(0xff), 1);
	salt[SALT_LEN] = '\0';

	for (n = 0; n < nb_ids; n++) {
		id = ids[n].prefix;
#ifndef CRYPT_GENSALT_IMPLEMENTS_DEFAULT_PREFIX
		(void)snprintf(buffer, sizeof buffer, "%s%s$", id, salt);
#else
                buffer = crypt_gensalt(id, ids[n].count, NULL, 0);
#endif
		if ((p = crypt(string, buffer)) == NULL)
			continue;
		if (strncmp(p, buffer, strlen(buffer)) != 0)
			continue;
		printf("%s\n", p);
		return;
	}

	salt[2] = 0;
	printf("%s\n", crypt(string, salt));
}

void
to64(char *s, long int v, int n)
{
	while (--n >= 0) {
		*s++ = itoa64[v & 0x3f];
		v >>= 6;
	}
}
