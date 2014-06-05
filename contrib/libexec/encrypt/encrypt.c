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

#define PASSWORD_LEN	128
#define SALT_LEN	16

static unsigned char itoa64[] =	 /* 0 ... 63 => ascii - 64 */
	"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static void to64(char *, long int, int);
static void print_passwd(const char *);

int
main(int argc, char *argv[])
{
	char	*buf, *lbuf;
	size_t	len;

	if (argc > 2) {
		fprintf(stderr, "usage: encrypt <string>\n");
		return (1);
	}

	if (argc == 2) {
		print_passwd(argv[1]);
		return (0);
	}

	lbuf = NULL;
	while ((buf = fgetln(stdin, &len))) {
		if (buf[len - 1] == '\n')
			buf[len - 1] = '\0';
		else {
			if ((lbuf = malloc(len + 1)) == NULL) {
				fprintf(stderr, "memory exhausted");
				return (1);
			}
			memcpy(lbuf, buf, len);
			lbuf[len] = '\0';
			buf = lbuf;
		}
		print_passwd(buf);
	}
	free(lbuf);

	return (0);
}

void
print_passwd(const char *string)
{
	const char     *ids[] = { "2a", "6", "5", "3", "2", "1", NULL };
	const char     *id;
	char		salt[SALT_LEN+1];
	char		buffer[PASSWORD_LEN];
	int		n;
	const char     *p;

	for (n = 0; n < SALT_LEN; ++n)
		to64(&salt[n], arc4random_uniform(0xff), 1);
	salt[SALT_LEN] = '\0';

	for (n = 0; ids[n]; n++) {
		id = ids[n];
		(void)snprintf(buffer, sizeof buffer, "$%s$%s$", id, salt);
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
