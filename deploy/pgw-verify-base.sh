#!/bin/bash
readonly SAFE_PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
PATH="${SAFE_PATH}"
export PATH
set -Eeuo pipefail

exec /usr/local/bin/pgw-agent verify-boot-base
