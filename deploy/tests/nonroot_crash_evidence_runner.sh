#!/bin/bash
set -Eeuo pipefail

readonly SAFE_PATH="/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
PATH="${SAFE_PATH}"
export PATH
readonly REQUIRED="${PGW_REQUIRE_NONROOT_CRASH_EVIDENCE:-0}"
[[ "${REQUIRED}" == 0 || "${REQUIRED}" == 1 ]] || {
    printf 'invalid PGW_REQUIRE_NONROOT_CRASH_EVIDENCE\n' >&2
    exit 2
}
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
readonly ROOT

skip_or_fail() {
    local message="$1"
    printf 'nonroot crash evidence unavailable: %s\n' "${message}" >&2
    [[ "${REQUIRED}" != 1 ]] || exit 77
    exit 0
}

[[ "$(uname -s)" == Linux ]] || skip_or_fail 'Linux is required'
((EUID == 0)) || skip_or_fail 'root orchestrator is required'
for command_name in setpriv getent tar find chown chmod mktemp stat install env rm id grep; do
    command -v "${command_name}" >/dev/null || skip_or_fail "missing ${command_name}"
done

# Use a deliberately account-less numeric identity.  In particular, never use
# the invoking administrator identity (often passwordless in CI) or any
# existing service account.  No passwd/group entry is created, so cleanup cannot leave host
# account or sudoers residue.
evidence_uid=''
for ((candidate = 60999; candidate >= 60000; candidate--)); do
    if ! getent passwd "${candidate}" >/dev/null && ! getent group "${candidate}" >/dev/null; then
        evidence_uid="${candidate}"
        break
    fi
done
[[ -n "${evidence_uid}" ]] || skip_or_fail 'no unused high numeric uid/gid in 60000..60999'
readonly evidence_uid
readonly evidence_gid="${evidence_uid}"
! getent passwd "${evidence_uid}" >/dev/null
! getent group "${evidence_gid}" >/dev/null

fixture="$(mktemp -d /var/lib/pgw-nonroot-crash-evidence.XXXXXXXX)"
cleanup() { rm -rf -- "${fixture}"; }
trap cleanup EXIT
# The source must remain traversable by the child.  Writable state is confined
# to separate uid-owned 0700 siblings, never below a root-only ancestor.
chmod 0755 "${fixture}"
install -d -o root -g root -m 0555 "${fixture}/source"
install -d -o "${evidence_uid}" -g "${evidence_gid}" -m 0700 \
    "${fixture}/work" "${fixture}/cache" "${fixture}/home"

(cd -- "${ROOT}" && tar --exclude=.git --exclude=dist -cf - .) | \
    tar -xf - -C "${fixture}/source"
if find "${fixture}/source" -type l -print -quit | grep -q .; then
    printf 'nonroot crash evidence source contains a symlink\n' >&2
    exit 1
fi
chown -R root:root "${fixture}/source"
find "${fixture}/source" -type d -exec chmod 0555 {} +
find "${fixture}/source" -type f -exec chmod 0444 {} +
[[ "$(stat -c '%u:%g:%a' "${fixture}")" == 0:0:755 ]]
[[ "$(stat -c '%u:%g:%a' "${fixture}/source")" == 0:0:555 ]]
[[ "$(stat -c '%u' /var/lib)" == 0 ]]
var_lib_mode="$(stat -c '%a' /var/lib)"
(( (8#${var_lib_mode} & 8#022) == 0 ))
for writable in work cache home; do
    [[ "$(stat -c '%u:%g:%a' "${fixture}/${writable}")" == \
       "${evidence_uid}:${evidence_gid}:700" ]]
done

setpriv --reuid="${evidence_uid}" --regid="${evidence_gid}" --clear-groups \
    --no-new-privs --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
    env -i PATH="${SAFE_PATH}" LANG=C LC_ALL=C \
    HOME="${fixture}/home" TMPDIR="${fixture}/work" GOCACHE="${fixture}/cache" \
    PGW_EVIDENCE_UID="${evidence_uid}" PGW_EVIDENCE_GID="${evidence_gid}" \
    PGW_EVIDENCE_SOURCE="${fixture}/source" \
    PGW_REQUIRE_LINUX_RESTORE_CRASH=1 PGW_TRANSACTION_SECTION=restore-crash \
    /bin/bash -c '
        set -Eeuo pipefail
        [[ "${EUID}" == "${PGW_EVIDENCE_UID}" ]]
        [[ "$(id -g)" == "${PGW_EVIDENCE_GID}" ]]
        status_value() {
            local wanted="$1" key value ignored
            while read -r key value ignored; do
                [[ "${key}" != "${wanted}:" ]] || { printf "%s\n" "${value}"; return 0; }
            done </proc/self/status
            return 1
        }
        for field in CapEff CapPrm CapInh CapAmb CapBnd; do
            value="$(status_value "${field}")"
            [[ "${value}" =~ ^0+$ ]] || {
                printf "evidence child retained %s=%s\n" "${field}" "${value}" >&2
                exit 1
            }
        done
        [[ "$(status_value NoNewPrivs)" == 1 ]]
        if command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
            printf "account-less evidence identity unexpectedly has sudo\n" >&2
            exit 1
        fi
        exec /bin/bash "${PGW_EVIDENCE_SOURCE}/deploy/tests/installer_transaction_test.sh"
    '

! getent passwd "${evidence_uid}" >/dev/null
! getent group "${evidence_gid}" >/dev/null

printf 'root-orchestrated nonroot crash evidence: PASS uid=%s\n' "${evidence_uid}"
