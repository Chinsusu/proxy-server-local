#!/bin/bash
readonly SAFE_PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
PATH="${SAFE_PATH}"
export PATH
set -Eeuo pipefail

# This checkout helper is deliberately never a privileged entrypoint. Routine
# production install/update/rollback starts at the static root-owned launcher,
# which clears the complete environment before Bash is invoked.
if ((EUID == 0)); then
    printf '[pgw-update] ERROR: root script entrypoint disabled; run /usr/local/sbin/pgw-release-launcher\n' >&2
    exit 126
fi
for name in PGW_SOURCE_DIR PGW_GO_BINARY PGW_REVIEWED_CHECKOUT PGW_REVIEWED_COMMIT BASH_ENV ENV LD_PRELOAD LD_LIBRARY_PATH; do
    [[ ! -v "${name}" ]] || { printf '[pgw-update] ERROR: forbidden caller environment: %s\n' "${name}" >&2; exit 64; }
done

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
if [[ "${1:-}" == --dry-run && "$#" == 1 ]]; then
    exec "${script_dir}/install-pgw.sh" --dry-run
fi
printf '[pgw-update] ERROR: production lifecycle requires: sudo /usr/local/sbin/pgw-release-launcher [arguments]\n' >&2
exit 126
