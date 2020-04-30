#!/bin/sh
set -eu

# Coverity Scan script
# Steps closely follow official documentation https://scan.coverity.com/download
# 
# USAGE: provide coverity project token as 'token' environment variable and run
# token=abcdedf ./ci/scripts/coverity_scan.sh
#
# Or uncomment this line and put token here. But do not commit this to git.
# token=""
project_name="OpenSMTPD%2FOpenSMTPD"
cov_analysis_url="https://scan.coverity.com/download/cxx/linux64"
maintainer="ihor@antonovs.family"

# Unconditionally go to the root level of the git repo.
# If you invoke it from outside of the repo go to
# the script location first
cd "$(dirname "$0")"
# This moves us to the root of the repo
cd "$(git rev-parse --show-toplevel)"

# Get short SHA of the HEAD
sha=$(git rev-parse --short HEAD)

# Download Coverity Build Tool if absent
set +x
# shellcheck disable=SC2154
md5sum -c ./ci/COVERITY.MD5SUM || wget $cov_analysis_url \
    --post-data "token=$token&project=$project_name" \
    -O cov-analysis-linux64.tgz
set -x

#Check MD5
md5sum -c ./ci/COVERITY.MD5SUM

# Extract Coverty Scan Tool
rm -rf ./cov-analysis-linux64
mkdir -p cov-analysis-linux64
tar xzf cov-analysis-linux64.tgz --strip 1 -C cov-analysis-linux64

# export PATH=$(pwd)/cov-analysis-linux64/bin:$PATH

# Build with cov-build
./bootstrap
./configure
cov-analysis-linux64/bin/cov-build --dir cov-int make

# Compress the rusults
tar czvf opensmtpd.tgz cov-int


# Submit the result to Coverity Scan
# Some parts are shamelessly taken from:
# https://scan.coverity.com/scripts/travisci_build_coverity_scan.sh
set +x
response=$(curl \
  --silent \
  --write-out "\n%{http_code}\n" \
  --form token="$token" \
  --form email="$maintainer" \
  --form file=@opensmtpd.tgz \
  --form version="portable-$sha" \
  --form description="daily scan" \
  "https://scan.coverity.com/builds?project=$project_name")
set -x

status_code=$(echo "$response" | sed -n '$p')

if [ "$status_code" != "200" ]; then
  text=$(echo "$response" | sed '$d')
  echo -e "Coverity Scan upload failed: $text"
  exit 1
fi



