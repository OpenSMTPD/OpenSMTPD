#!/bin/sh
set -euxo pipefail
BASEDIR=$(dirname $0)

echo "Testing TLS"
"$BASEDIR/certificate_test/test.sh"
