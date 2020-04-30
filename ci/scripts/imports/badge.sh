#!/bin/sh
# Copyright 2019 Neovim Project Contributors (https://neovim.io/)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Helper functions for getting badges.

# Get code quality color.
# ${1}:   Amount of bugs actually found.
# ${2}:   Maximum number of bugs above which color will be red. Defaults to 20.
# ${3}:   Maximum number of bugs above which color will be yellow. Defaults to
#         $1 / 2.
# Output: 24-bit hexadecimal representation of the color (xxxxxx).
get_code_quality_color() {
  bugs=$1 ; shift  # shift will fail if there is no argument
  max_bugs=${1:-20}
  yellow_threshold=${2:-$(( max_bugs / 2 ))}

  red=255
  green=255
  blue=0

  bugs=$(( bugs < max_bugs ? bugs : max_bugs))
  if test $bugs -ge "$yellow_threshold" ; then
    green=$(( 255 - 255 * (bugs - yellow_threshold) / yellow_threshold ))
  else
    red=$(( 255 * bugs / yellow_threshold ))
  fi

  printf "%02x%02x%02x" $red $green $blue
}

# Get code quality badge.
# ${1}:   Amount of bugs actually found.
# ${2}:   Badge text.
# ${3}:   Directory where to save badge to.
# ${3}:   Maximum number of bugs above which color will be red. Defaults to 20.
# ${4}:   Maximum number of bugs above which color will be yellow. Defaults to
#         $1 / 2.
# Output: 24-bit hexadecimal representation of the color (xxxxxx).
download_badge() {
  bugs=$1 ; shift
  badge_text="$1" ; shift
  reports_dir="$1" ; shift
  max_bugs=${1:-20}
  yellow_threshold=${2:-$(( max_bugs / 2 ))}

  code_quality_color="$(
    get_code_quality_color $bugs $max_bugs $yellow_threshold)"
  badge="${badge_text}-${bugs}-${code_quality_color}"

  rm -f "$reports_dir/badge.svg"
  
  response="$(
    curl --tlsv1 "https://img.shields.io/badge/${badge}.svg" \
      -o"$reports_dir/badge.svg" 2>&1)"
  
  if ! grep -F 'xmlns="http://www.w3.org/2000/svg"' "$reports_dir/badge.svg"  ; then
    echo "Failed to download badge to $reports_dir: $response"
    rm -f "$reports_dir/badge.svg"
  fi
}
