#!/bin/sh

# Generate self-signed SSL certs
# Usage: ./generate_certs.sh

days=3560           # 10 years
config="$(dirname "$0")/ssl.conf"
cert="open.smtpd.cert"
key="open.smtpd.key"
csr="open.smtpd.csr"

# Key + CSR generation:
openssl req \
    -new \
    -x509 \
    -newkey rsa:2048 \
    -sha256 \
    -nodes \
    -keyout $key \
    -out $csr \
    -days $days \
    -config "$config"

# Certificate generation:
openssl req \
    -new \
    -x509 \
    -newkey rsa:2048 \
    -days $days \
    -nodes  \
    -config "$config" \
    -keyout $key  \
    -out $cert
