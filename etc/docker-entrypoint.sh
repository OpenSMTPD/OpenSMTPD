#!/bin/sh

# Copyright (c) 2019 Gilles Chehade <gilles@poolp.org>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
# Build environment container
# This container is also used for testing so that final container stay clean

set -euxo pipefail

# Because docker will overwrite permissions on volume mounted directory
# to default (which is 755) we can't rely on build-time commands to fix
# permissions

echo "Ensure correct permissions on /var/spool/smtpd"

mkdir -p /var/spool/smtpd
mkdir -p /var/spool/smtpd/corrupt
mkdir -p /var/spool/smtpd/incoming
mkdir -p /var/spool/smtpd/purge
mkdir -p /var/spool/smtpd/queue
mkdir -p /var/spool/smtpd/temporary

chmod 711 /var/spool/smtpd
chmod 700 /var/spool/smtpd/corrupt
chmod 700 /var/spool/smtpd/incoming
chmod 700 /var/spool/smtpd/purge
chmod 700 /var/spool/smtpd/queue
chmod 700 /var/spool/smtpd/temporary

chown _smtpq /var/spool/smtpd/corrupt
chown _smtpq /var/spool/smtpd/incoming
chown _smtpq /var/spool/smtpd/purge
chown _smtpq /var/spool/smtpd/queue
chown _smtpq /var/spool/smtpd/temporary

smtpd -d "$@"
