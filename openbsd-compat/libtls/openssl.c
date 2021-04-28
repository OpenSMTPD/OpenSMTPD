#include "includes.h"

#include <sys/uio.h>

#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>

#define X509_LOOKUP_add_mem(x,iov,type) \
		X509_LOOKUP_ctrl((x),X509_L_MEM,(const char *)(iov),\
		(long)(type),NULL)

#define X509_L_MEM               3

X509_LOOKUP_METHOD *
X509_LOOKUP_mem(void);

int
X509_STORE_load_mem(X509_STORE *ctx, void *buf, int len)
{
        X509_LOOKUP             *lookup;
        struct iovec             iov;
        lookup = X509_STORE_add_lookup(ctx, X509_LOOKUP_mem());
        if (lookup == NULL)
                return (0);
        iov.iov_base = buf;
        iov.iov_len = len;
        if (X509_LOOKUP_add_mem(lookup, &iov, X509_FILETYPE_PEM) != 1)
                return (0);
        return (1);
}

int
SSL_CTX_load_verify_mem(SSL_CTX *ctx, void *buf, int len)
{
    return (X509_STORE_load_mem(SSL_CTX_get_cert_store(ctx), buf, len));
}
