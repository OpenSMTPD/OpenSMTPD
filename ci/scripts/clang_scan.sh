#!/bin/sh
set -eu

# Unconditionally go to the root level of the git repo.
# If you invoke it from outside of the repo go to
# the script location first
cd "$(dirname "$0")"
cd "$(git rev-parse --show-toplevel)"

# Clang Scan script
# 
# USAGE: 
# - clang must be installed
# - make sure you have clean repository, 
#   e.g. git clean -ffdx
# - if you want to download github badge set CLANG_SCAN_BADGE_REQUIRED variable
# - Run script from anywhere inside the repository
#   ./ci/scripts/clang_scan.sh
#   or 
#   CLANG_SCAN_BADGE_REQUIRED=1 ./ci/scripts/clang_scan.sh
# 

if ! type scan-build > /dev/null; then
  echo "clang scan-build is missing"
  exit 1
fi

# Unconditionally go to the root level of the git repo.
# If you invoke it from outside of the repo go to
# the script location first
cd "$(dirname "$0")"
# This moves us to the root of the repo
cd "$(git rev-parse --show-toplevel)"

# Get short SHA of the HEAD
sha=$(git rev-parse --short HEAD)

results_dir=${CLANG_SCAN_RESULTS_DIR:-clang-report}
mkdir -p "$results_dir"
 
# Build with scan-build
./bootstrap
./configure
scan-build -o "$results_dir" \
    --keep-empty \
    --html-title="OpenSMTPD $sha" make


set -x
# conditionally generate badge
if [ -z "${CLANG_SCAN_BADGE_REQUIRED:-}" ]; then
  echo "Skipping badge generation"
else
  echo "Generating badge"
  . ci/scripts/imports/badge.sh
  cd "$results_dir"
  cd "$( find  . -type d | sort | tail -n1 )"
  issues_nr="$( find . -name "report-*" | wc -l)"
  download_badge "$issues_nr" "clang analysis" "$(pwd)" 30
fi
