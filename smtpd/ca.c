/*	$OpenBSD$	*/

/*
 * Copyright (c) 2012 Gilles Chehade <gilles@poolp.org>
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

#include <openssl/err.h>
#include <openssl/ssl.h>

int	ca_X509_verify(X509 *, const char *, const char *, const char **);

int
ca_X509_verify(X509 *certificate, const char *CAfile, const char *CRLfile, const char **errstr)
{
	X509_STORE	*store = NULL;
	X509_LOOKUP	*lookup = NULL;
	X509_STORE_CTX	*xsc = NULL;
	int		i = 0;

	if ((store = X509_STORE_new()) == NULL)
		goto end;

	if (CAfile) {
		if ((lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file())) == NULL)
			goto end;
		
		if (! X509_LOOKUP_load_file(lookup, CAfile, X509_FILETYPE_PEM))
			goto end;

/*
//		if ((lookup = X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir())) == NULL)
//			goto end;
//
//		X509_LOOKUP_add_dir(lookup, "/etc/ssl", X509_FILETYPE_PEM);
*/
	}

	if ((xsc = X509_STORE_CTX_new()) == NULL)
		goto end;

	if (! X509_STORE_CTX_init(xsc, store, certificate, 0))
		goto end;

	i = X509_verify_cert(xsc);

end:
	*errstr = NULL;
	if (i <= 0) {
		if (ERR_peek_last_error())
			*errstr = ERR_error_string(ERR_peek_last_error(), NULL);
	}

	if (xsc)
		X509_STORE_CTX_free(xsc);
	if (store)
		X509_STORE_free(store);
	return i > 0 ? 1 : 0;
}
