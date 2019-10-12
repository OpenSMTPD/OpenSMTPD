#!/bin/sh
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
