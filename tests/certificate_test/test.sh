#!/bin/sh
set -euxo pipefail
BASEDIR=$(dirname $0)

# Setup TLS
mkdir -p /etc/ssl/private/sites/
openssl genrsa -out /etc/ssl/private/sites/site.key 4096
openssl req -new -x509 -key /etc/ssl/private/sites/site.key -out /etc/ssl/private/sites/fullchain.cer -subj "/CN='localhost'"
chmod 600 /etc/ssl/private/sites/site.key
chmod 644 /etc/ssl/private/sites/fullchain.cer

smtpd -dv -f "$BASEDIR/smtpd.conf" &

#Wait for smtpd to be ready to receive connections
sleep 3

#OpenSSL is crazy and will treat a capital "R" or "Q" as a command without the -quiet flag
#OpenSMTPD doesn't support pipelining, so wait 0.1 seconds between lines
awk '{print $0; system("sleep .1");}' "$BASEDIR/../test_email.txt" | \
    openssl s_client -quiet -connect localhost:25 -starttls smtp
