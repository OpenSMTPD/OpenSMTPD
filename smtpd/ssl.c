/*	$OpenBSD: ssl.c,v 1.93 2019/06/05 06:40:13 gilles Exp $	*/

/*
 * Copyright (c) 2008 Pierre-Yves Ritschard <pyr@openbsd.org>
 * Copyright (c) 2008 Reyk Floeter <reyk@openbsd.org>
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
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <ctype.h>
#include <event.h>
#include <fcntl.h>
#include <imsg.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tls.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/ecdsa.h>
#include <openssl/dh.h>
#include <openssl/bn.h>

#include "log.h"
#include "ssl.h"
#include "boguskeys.h"

void
hash_x509(X509 *cert, char *hash, size_t hashlen);

void
ssl_init(void)
{
	static int	inited = 0;

	if (inited)
		return;

	SSL_library_init();
	SSL_load_error_strings();

	OpenSSL_add_all_algorithms();

	/* Init hardware crypto engines. */
	ENGINE_load_builtin_engines();
	ENGINE_register_all_complete();

	inited = 1;
}

char *
ssl_load_file(const char *name, off_t *len, mode_t perm)
{
	struct stat	 st;
	off_t		 size;
	char		*buf = NULL;
	int		 fd, saved_errno;
	char		 mode[12];

	if ((fd = open(name, O_RDONLY)) == -1)
		return (NULL);
	if (fstat(fd, &st) != 0)
		goto fail;
	if (st.st_uid != 0) {
		log_warnx("warn:  %s: not owned by uid 0", name);
		errno = EACCES;
		goto fail;
	}
	if (st.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO) & ~perm) {
		strmode(perm, mode);
		log_warnx("warn:  %s: insecure permissions: must be at most %s",
		    name, &mode[1]);
		errno = EACCES;
		goto fail;
	}
	size = st.st_size;
	if ((buf = calloc(1, size + 1)) == NULL)
		goto fail;
	if (read(fd, buf, size) != size)
		goto fail;
	close(fd);

	*len = size + 1;
	return (buf);

fail:
	free(buf);
	saved_errno = errno;
	close(fd);
	errno = saved_errno;
	return (NULL);
}

static int
ssl_password_cb(char *buf, int size, int rwflag, void *u)
{
	int	ret = 0;
	size_t	len;
	char	*pass;

	pass = getpass((const char *)u);
	if (pass == NULL)
		return 0;
	len = strlen(pass);
	if (strlcpy(buf, pass, size) >= (size_t)size)
		goto end;
	ret = len;
end:
	if (len)
		explicit_bzero(pass, len);
	return ret;
}

char *
ssl_load_key(const char *name, off_t *len, char *pass, mode_t perm, const char *pkiname)
{
	FILE		*fp = NULL;
	EVP_PKEY	*key = NULL;
	BIO		*bio = NULL;
	long		 size;
	char		*data, *buf, *filebuf;
	struct stat	 st;
	char		 mode[12];
	char		 prompt[2048];

	/* Initialize SSL library once */
	ssl_init();

	/*
	 * Read (possibly) encrypted key from file
	 */
	if ((fp = fopen(name, "r")) == NULL)
		return (NULL);
	if ((filebuf = malloc_conceal(BUFSIZ)) == NULL)
		goto fail;
	setvbuf(fp, filebuf, _IOFBF, BUFSIZ);

	if (fstat(fileno(fp), &st) != 0)
		goto fail;
	if (st.st_uid != 0) {
		log_warnx("warn:  %s: not owned by uid 0", name);
		errno = EACCES;
		goto fail;
	}
	if (st.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO) & ~perm) {
		strmode(perm, mode);
		log_warnx("warn:  %s: insecure permissions: must be at most %s",
		    name, &mode[1]);
		errno = EACCES;
		goto fail;
	}

	(void)snprintf(prompt, sizeof prompt, "passphrase for %s: ", pkiname);
	key = PEM_read_PrivateKey(fp, NULL, ssl_password_cb, prompt);
	fclose(fp);
	fp = NULL;
	freezero(filebuf, BUFSIZ);
	filebuf = NULL;
	if (key == NULL)
		goto fail;
	/*
	 * Write unencrypted key to memory buffer
	 */
	if ((bio = BIO_new(BIO_s_mem())) == NULL)
		goto fail;
	if (!PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL))
		goto fail;
	if ((size = BIO_get_mem_data(bio, &data)) <= 0)
		goto fail;
	if ((buf = calloc_conceal(1, size + 1)) == NULL)
		goto fail;
	memcpy(buf, data, size);

	BIO_free_all(bio);
	EVP_PKEY_free(key);

	*len = (off_t)size + 1;
	return (buf);

fail:
	ssl_error("ssl_load_key");
	BIO_free_all(bio);
	EVP_PKEY_free(key);
	if (fp)
		fclose(fp);
	freezero(filebuf, BUFSIZ);
	return (NULL);
}

int
ssl_load_certificate(struct pki *p, const char *pathname)
{
	p->pki_cert = ssl_load_file(pathname, &p->pki_cert_len, 0755);
	if (p->pki_cert == NULL)
		return 0;
	return 1;
}

int
ssl_load_keyfile(struct pki *p, const char *pathname, const char *pkiname)
{
	char	pass[1024];

	p->pki_key = ssl_load_key(pathname, &p->pki_key_len, pass, 0740, pkiname);
	if (p->pki_key == NULL)
		return 0;
	return 1;
}

int
ssl_load_cafile(struct ca *c, const char *pathname)
{
	c->ca_cert = ssl_load_file(pathname, &c->ca_cert_len, 0755);
	if (c->ca_cert == NULL)
		return 0;
	return 1;
}

const char *
ssl_to_text(const SSL *ssl)
{
	static char buf[256];

	(void)snprintf(buf, sizeof buf, "%s:%s:%d",
	    SSL_get_version(ssl),
	    SSL_get_cipher_name(ssl),
	    SSL_get_cipher_bits(ssl, NULL));

	return (buf);
}

void
ssl_error(const char *where)
{
	unsigned long	code;
	char		errbuf[128];

	for (; (code = ERR_get_error()) != 0 ;) {
		ERR_error_string_n(code, errbuf, sizeof(errbuf));
		log_debug("debug: SSL library error: %s: %s", where, errbuf);
	}
}


/*
 * This function is a horrible hack but for RSA privsep to work a private key
 * with correct size needs to be loaded into the tls config.
 */
int
tls_ctx_fake_private_key(char *buf, off_t len, const char **fake_key,
    X509 **x509ptr, EVP_PKEY **pkeyptr, char *hash)
{
	BIO		*in;
	EVP_PKEY	*pkey = NULL;
	X509		*x509 = NULL;
	int		 ret = -1, keylen;
	RSA		*rsa = NULL;
	EC_KEY		*eckey = NULL;

	if ((in = BIO_new_mem_buf(buf, len)) == NULL) {
		log_warnx("%s: BIO_new_mem_buf failed", __func__);
		return (0);
	}

	if ((x509 = PEM_read_bio_X509(in, NULL, NULL, NULL)) == NULL) {
		log_warnx("%s: PEM_read_bio_X509 failed", __func__);
		goto fail;
	}

	if ((pkey = X509_get_pubkey(x509)) == NULL) {
		log_warnx("%s: X509_get_pubkey failed", __func__);
		goto fail;
	}

	if (((rsa = EVP_PKEY_get1_RSA(pkey)) == NULL &&
		(eckey = EVP_PKEY_get1_EC_KEY(pkey)) == NULL)) {
		log_warnx("%s: EVP_PKEY_get1_RSA/EC_KEY failed", __func__);
		goto fail;
	}

	hash_x509(x509, hash, TLS_CERT_HASH_SIZE);
	if (rsa)
		RSA_set_ex_data(rsa, 0, hash);
	if (eckey)
		ECDSA_set_ex_data(eckey, 0, hash);

	keylen = EVP_PKEY_size(pkey) * 8;
	switch(keylen) {
	case 1024:
		*fake_key = bogus_1024;
		ret = sizeof(bogus_1024);
		break;
	case 2048:
		*fake_key = bogus_2048;
		ret = sizeof(bogus_2048);
		break;
	case 4096:
		*fake_key = bogus_4096;
		ret = sizeof(bogus_4096);
		break;
	case 8192:
		*fake_key = bogus_8192;
		ret = sizeof(bogus_8192);
		break;
	default:
		log_warnx("%s: key size %d not support", __func__, keylen);
		ret = -1;
		break;
	}

	if (ret != -1) {
		if (x509ptr) {
			*x509ptr = x509;
			x509 = NULL;
		}
		if (pkeyptr) {
			*pkeyptr = pkey;
			pkey = NULL;
		}
	}

fail:
	BIO_free(in);

	if (rsa)
		RSA_free(rsa);
	if (eckey)
		EC_KEY_free(eckey);
	if (pkey)
		EVP_PKEY_free(pkey);
	if (x509)
		X509_free(x509);

	return (ret);
}

void
hash_x509(X509 *cert, char *hash, size_t hashlen)
{
	static const char	hex[] = "0123456789abcdef";
	size_t			off;
	char			digest[EVP_MAX_MD_SIZE];
	int		 	dlen, i;

	if (X509_pubkey_digest(cert, EVP_sha256(), digest, &dlen) != 1)
		fatalx("%s: X509_pubkey_digest failed", __func__);

	if (hashlen < 2 * dlen + sizeof("SHA256:"))
		fatalx("%s: hash buffer to small", __func__);

	off = strlcpy(hash, "SHA256:", hashlen);

	for (i = 0; i < dlen; i++) {
		hash[off++] = hex[(digest[i] >> 4) & 0x0f];
		hash[off++] = hex[digest[i] & 0x0f];
	}
	hash[off] = 0;
}
