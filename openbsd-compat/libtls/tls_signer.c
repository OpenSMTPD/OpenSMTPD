/* $OpenBSD: tls_signer.c,v 1.8 2023/06/18 17:50:28 tb Exp $ */
/*
 * Copyright (c) 2021 Eric Faurot <eric@openbsd.org>
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

#include <limits.h>

#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

#include "tls.h"
#include "tls_internal.h"

struct tls_signer_key {
	char *hash;
	RSA *rsa;
	EC_KEY *ecdsa;
	struct tls_signer_key *next;
};

struct tls_signer {
	struct tls_error error;
	struct tls_signer_key *keys;
};

struct tls_signer *
tls_signer_new(void)
{
	struct tls_signer *signer;

	if ((signer = calloc(1, sizeof(*signer))) == NULL)
		return (NULL);

	return (signer);
}

void
tls_signer_free(struct tls_signer *signer)
{
	struct tls_signer_key *skey;

	if (signer == NULL)
		return;

	tls_error_clear(&signer->error);

	while (signer->keys) {
		skey = signer->keys;
		signer->keys = skey->next;
		RSA_free(skey->rsa);
		EC_KEY_free(skey->ecdsa);
		free(skey->hash);
		free(skey);
	}

	free(signer);
}

const char *
tls_signer_error(struct tls_signer *signer)
{
	return (signer->error.msg);
}

int
tls_signer_add_keypair_mem(struct tls_signer *signer, const uint8_t *cert,
    size_t cert_len, const uint8_t *key, size_t key_len)
{
	struct tls_signer_key *skey = NULL;
	char *errstr = "unknown";
	int ssl_err;
	EVP_PKEY *pkey = NULL;
	X509 *x509 = NULL;
	BIO *bio = NULL;
	char *hash = NULL;

	/* Compute certificate hash */
	if ((bio = BIO_new_mem_buf(cert, cert_len)) == NULL) {
		tls_error_setx(&signer->error,
		    "failed to create certificate bio");
		goto err;
	}
	if ((x509 = PEM_read_bio_X509(bio, NULL, tls_password_cb,
	    NULL)) == NULL) {
		if ((ssl_err = ERR_peek_error()) != 0)
			errstr = ERR_error_string(ssl_err, NULL);
		tls_error_setx(&signer->error, "failed to load certificate: %s",
		    errstr);
		goto err;
	}
	if (tls_cert_pubkey_hash(x509, &hash) == -1) {
		tls_error_setx(&signer->error,
		    "failed to get certificate hash");
		goto err;
	}

	X509_free(x509);
	x509 = NULL;
	BIO_free(bio);
	bio = NULL;

	/* Read private key */
	if ((bio = BIO_new_mem_buf(key, key_len)) == NULL) {
		tls_error_setx(&signer->error, "failed to create key bio");
		goto err;
	}
	if ((pkey = PEM_read_bio_PrivateKey(bio, NULL, tls_password_cb,
	    NULL)) == NULL) {
		tls_error_setx(&signer->error, "failed to read private key");
		goto err;
	}

	if ((skey = calloc(1, sizeof(*skey))) == NULL) {
		tls_error_set(&signer->error, "failed to create key entry");
		goto err;
	}
	skey->hash = hash;
	if ((skey->rsa = EVP_PKEY_get1_RSA(pkey)) == NULL &&
	    (skey->ecdsa = EVP_PKEY_get1_EC_KEY(pkey)) == NULL) {
		tls_error_setx(&signer->error, "unknown key type");
		goto err;
	}

	skey->next = signer->keys;
	signer->keys = skey;
	EVP_PKEY_free(pkey);
	BIO_free(bio);

	return (0);

 err:
	EVP_PKEY_free(pkey);
	X509_free(x509);
	BIO_free(bio);
	free(hash);
	free(skey);

	return (-1);
}

int
tls_signer_add_keypair_file(struct tls_signer *signer, const char *cert_file,
    const char *key_file)
{
	char *cert = NULL, *key = NULL;
	size_t cert_len, key_len;
	int rv = -1;

	if (tls_config_load_file(&signer->error, "certificate", cert_file,
	    &cert, &cert_len) == -1)
		goto err;

	if (tls_config_load_file(&signer->error, "key", key_file, &key,
	    &key_len) == -1)
		goto err;

	rv = tls_signer_add_keypair_mem(signer, cert, cert_len, key, key_len);

 err:
	free(cert);
	free(key);

	return (rv);
}

static int
tls_sign_rsa(struct tls_signer *signer, struct tls_signer_key *skey,
    const uint8_t *input, size_t input_len, int padding_type,
    uint8_t **out_signature, size_t *out_signature_len)
{
	int rsa_padding, rsa_size, signature_len;
	char *signature = NULL;

	*out_signature = NULL;
	*out_signature_len = 0;

	if (padding_type == TLS_PADDING_NONE) {
		rsa_padding = RSA_NO_PADDING;
	} else if (padding_type == TLS_PADDING_RSA_PKCS1) {
		rsa_padding = RSA_PKCS1_PADDING;
	} else {
		tls_error_setx(&signer->error, "invalid RSA padding type (%d)",
		    padding_type);
		return (-1);
	}

	if (input_len > INT_MAX) {
		tls_error_setx(&signer->error, "input too large");
		return (-1);
	}
	if ((rsa_size = RSA_size(skey->rsa)) <= 0) {
		tls_error_setx(&signer->error, "invalid RSA size: %d",
		    rsa_size);
		return (-1);
	}
	if ((signature = calloc(1, rsa_size)) == NULL) {
		tls_error_set(&signer->error, "RSA signature");
		return (-1);
	}

	if ((signature_len = RSA_private_encrypt((int)input_len, input,
	    signature, skey->rsa, rsa_padding)) <= 0) {
		/* XXX - include further details from libcrypto. */
		tls_error_setx(&signer->error, "RSA signing failed");
		free(signature);
		return (-1);
	}

	*out_signature = signature;
	*out_signature_len = (size_t)signature_len;

	return (0);
}

static int
tls_sign_ecdsa(struct tls_signer *signer, struct tls_signer_key *skey,
    const uint8_t *input, size_t input_len, int padding_type,
    uint8_t **out_signature, size_t *out_signature_len)
{
	unsigned char *signature;
	int signature_len;

	*out_signature = NULL;
	*out_signature_len = 0;

	if (padding_type != TLS_PADDING_NONE) {
		tls_error_setx(&signer->error, "invalid ECDSA padding");
		return (-1);
	}

	if (input_len > INT_MAX) {
		tls_error_setx(&signer->error, "digest too large");
		return (-1);
	}
	if ((signature_len = ECDSA_size(skey->ecdsa)) <= 0) {
		tls_error_setx(&signer->error, "invalid ECDSA size: %d",
		    signature_len);
		return (-1);
	}
	if ((signature = calloc(1, signature_len)) == NULL) {
		tls_error_set(&signer->error, "ECDSA signature");
		return (-1);
	}

	if (!ECDSA_sign(0, input, input_len, signature, &signature_len,
	    skey->ecdsa)) {
		/* XXX - include further details from libcrypto. */
		tls_error_setx(&signer->error, "ECDSA signing failed");
		free(signature);
		return (-1);
	}

	*out_signature = signature;
	*out_signature_len = signature_len;

	return (0);
}

int
tls_signer_sign(struct tls_signer *signer, const char *pubkey_hash,
    const uint8_t *input, size_t input_len, int padding_type,
    uint8_t **out_signature, size_t *out_signature_len)
{
	struct tls_signer_key *skey;

	*out_signature = NULL;
	*out_signature_len = 0;

	for (skey = signer->keys; skey; skey = skey->next)
		if (!strcmp(pubkey_hash, skey->hash))
			break;

	if (skey == NULL) {
		tls_error_setx(&signer->error, "key not found");
		return (-1);
	}

	if (skey->rsa != NULL)
		return tls_sign_rsa(signer, skey, input, input_len,
		    padding_type, out_signature, out_signature_len);

	if (skey->ecdsa != NULL)
		return tls_sign_ecdsa(signer, skey, input, input_len,
		    padding_type, out_signature, out_signature_len);

	tls_error_setx(&signer->error, "unknown key type");

	return (-1);
}

static int
tls_rsa_priv_enc(int from_len, const unsigned char *from, unsigned char *to,
    RSA *rsa, int rsa_padding)
{
	struct tls_config *config;
	uint8_t *signature = NULL;
	size_t signature_len = 0;
	const char *pubkey_hash;
	int padding_type;

	/*
	 * This function is called via RSA_private_encrypt() and has to conform
	 * to its calling convention/signature. The caller is required to
	 * provide a 'to' buffer of at least RSA_size() bytes.
	 */

	pubkey_hash = RSA_get_ex_data(rsa, 0);
	config = RSA_get_ex_data(rsa, 1);

	if (pubkey_hash == NULL || config == NULL)
		goto err;

	if (rsa_padding == RSA_NO_PADDING) {
		padding_type = TLS_PADDING_NONE;
	} else if (rsa_padding == RSA_PKCS1_PADDING) {
		padding_type = TLS_PADDING_RSA_PKCS1;
	} else {
		goto err;
	}

	if (from_len < 0)
		goto err;

	if (config->sign_cb(config->sign_cb_arg, pubkey_hash, from, from_len,
	    padding_type, &signature, &signature_len) == -1)
		goto err;

	if (signature_len > INT_MAX || (int)signature_len > RSA_size(rsa))
		goto err;

	memcpy(to, signature, signature_len);
	free(signature);

	return ((int)signature_len);

 err:
	free(signature);

	return (-1);
}

RSA_METHOD *
tls_signer_rsa_method(void)
{
	static RSA_METHOD *rsa_method = NULL;

	if (rsa_method != NULL)
		goto out;

	rsa_method = RSA_meth_new("libtls RSA method", 0);
	if (rsa_method == NULL)
		goto out;

	RSA_meth_set_priv_enc(rsa_method, tls_rsa_priv_enc);

 out:
	return (rsa_method);
}

static ECDSA_SIG *
tls_ecdsa_do_sign(const unsigned char *dgst, int dgst_len, const BIGNUM *inv,
    const BIGNUM *rp, EC_KEY *eckey)
{
	struct tls_config *config;
	ECDSA_SIG *ecdsa_sig = NULL;
	uint8_t *signature = NULL;
	size_t signature_len = 0;
	const unsigned char *p;
	const char *pubkey_hash;

	/*
	 * This function is called via ECDSA_do_sign_ex() and has to conform
	 * to its calling convention/signature.
	 */

	pubkey_hash = EC_KEY_get_ex_data(eckey, 0);
	config = EC_KEY_get_ex_data(eckey, 1);

	if (pubkey_hash == NULL || config == NULL)
		goto err;

	if (dgst_len < 0)
		goto err;

	if (config->sign_cb(config->sign_cb_arg, pubkey_hash, dgst, dgst_len,
	    TLS_PADDING_NONE, &signature, &signature_len) == -1)
		goto err;

	p = signature;
	if ((ecdsa_sig = d2i_ECDSA_SIG(NULL, &p, signature_len)) == NULL)
		goto err;

	free(signature);

	return (ecdsa_sig);

 err:
	free(signature);

	return (NULL);
}

EC_KEY_METHOD *
tls_signer_ecdsa_method(void)
{
	static EC_KEY_METHOD *ecdsa_method = NULL;
	const EC_KEY_METHOD *default_method;
	int (*keygen)(EC_KEY *key);
	int (*compute_key)(void *out, size_t outlen, const EC_POINT *pub_key,
	    EC_KEY *ecdh, void *(*KDF) (const void *in, size_t inlen, void *out,
	    size_t *outlen));
	int (*sign)(int type, const unsigned char *dgst, int dlen,
	    unsigned char *sig, unsigned int *siglen,
	    const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey);
	int (*sign_setup)(EC_KEY *eckey, BN_CTX *ctx_in,
	    BIGNUM **kinvp, BIGNUM **rp);
	int (*verify)(int type, const unsigned char *dgst, int dgst_len,
	    const unsigned char *sigbuf, int sig_len, EC_KEY *eckey);
	int (*verify_sig)(const unsigned char *dgst, int dgst_len,
	    const ECDSA_SIG *sig, EC_KEY *eckey);

	if (ecdsa_method != NULL)
		goto out;

	ecdsa_method = EC_KEY_METHOD_new(NULL);
	if (ecdsa_method == NULL)
		goto out;

	default_method = EC_KEY_get_default_method();

	EC_KEY_METHOD_get_keygen(default_method, &keygen);
	EC_KEY_METHOD_set_keygen(ecdsa_method, keygen);

	EC_KEY_METHOD_get_compute_key(default_method, &compute_key);
	EC_KEY_METHOD_set_compute_key(ecdsa_method, compute_key);

	EC_KEY_METHOD_get_sign(default_method, &sign, &sign_setup, NULL);
	EC_KEY_METHOD_set_sign(ecdsa_method, sign, sign_setup,
	    tls_ecdsa_do_sign);

	EC_KEY_METHOD_get_verify(default_method, &verify, &verify_sig);
	EC_KEY_METHOD_set_verify(ecdsa_method, verify, verify_sig);

 out:
	return (ecdsa_method);
}
