#!/bin/bash
readonly SAFE_PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
PATH="${SAFE_PATH}"
export PATH
set -Eeuo pipefail

if ((EUID == 0)); then
    printf '[pgw-update-compat] ERROR: root script entrypoint disabled; run /usr/local/sbin/pgw-release-launcher\n' >&2
    exit 126
fi
for name in PGW_SOURCE_DIR PGW_GO_BINARY PGW_REVIEWED_CHECKOUT PGW_REVIEWED_COMMIT BASH_ENV ENV LD_PRELOAD LD_LIBRARY_PATH; do
    [[ ! -v "${name}" ]] || { printf '[pgw-update-compat] ERROR: forbidden caller environment: %s\n' "${name}" >&2; exit 64; }
done

printf '[pgw-update-compat] ERROR: retired; use sudo /usr/local/sbin/pgw-release-launcher\n' >&2
exit 126
