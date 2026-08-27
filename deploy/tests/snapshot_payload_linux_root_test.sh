#!/bin/bash
# Linux/root runtime proof for the shell/Python snapshot integration. The Go
# helper's precise link/fsync failpoints are unit-tested in cmd/snapshot-crypt;
# this harness proves the real helper is wired through direct ciphertext capture
# and a private stage before descriptor-bound host restore.
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
required="${PGW_REQUIRE_SNAPSHOT_PAYLOAD_ROOT_EVIDENCE:-0}"
[[ "${required}" == 0 || "${required}" == 1 ]] || exit 2
skip_or_fail() {
    printf 'snapshot payload Linux/root harness: SKIP %s\n' "$1"
    [[ "${required}" != 1 ]] || exit 77
    exit 0
}
[[ "$(uname -s)" == Linux ]] || skip_or_fail 'Linux required'
((EUID == 0)) || skip_or_fail 'isolated root required'
command -v go >/dev/null || skip_or_fail 'Go compiler unavailable'

fixture="$(mktemp -d /run/pgw-snapshot-payload-test.XXXXXXXX)"
trap 'rm -rf -- "${fixture}"' EXIT
chmod 0700 "${fixture}"
helper="${fixture}/pgw-snapshot-crypt"
(cd "${ROOT}" && CGO_ENABLED=0 GOENV=off go build -o "${helper}" ./cmd/snapshot-crypt)

source_root="${fixture}/source"
snapshot="${fixture}/snapshot"
stage="${fixture}/stage"
host_root="${fixture}/host"
install -d -m 0700 "${source_root}/var/lib/pgw" "${snapshot}/key-sequences" "${host_root}/var/lib"
printf 'root-runtime-canary\n' >"${source_root}/var/lib/pgw/pgw.db"
chmod 0600 "${source_root}/var/lib/pgw/pgw.db"
printf '0123456789abcdef0123456789abcdef' >"${fixture}/key"
chmod 0600 "${fixture}/key"
printf 'present\t/var/lib/pgw\n' >"${snapshot}/manifest"

/usr/bin/python3 -I "${ROOT}/deploy/snapshot_payload.py" capture \
    "${snapshot}" "${source_root}" "${fixture}/key" key.root.runtime "${helper}" \
    install.root.runtime release.root.runtime \
    "${snapshot}/key-sequences/key-sequence-$(printf '%s' key.root.runtime | sha256sum | awk '{print $1}').json"
[[ -d "${snapshot}/objects" && ! -e "${snapshot}/files" ]]
find "${snapshot}/objects" -type f -name '*.pgwsnap' -print -quit | grep -q .
/usr/bin/python3 -I "${ROOT}/deploy/snapshot_payload.py" verify "${snapshot}" "${fixture}/key" "${helper}"

# Production state trees are service-owned (legacy /var/lib/pgw is owned by
# the API account, not root). Under the quiesced capture contract the helper
# must accept ancestors owned by the source file's own principal.
service_root="${fixture}/service-source"
service_snapshot="${fixture}/service-snapshot"
install -d -m 0700 "${service_root}/var/lib/pgw" "${service_snapshot}/key-sequences"
printf 'service-owned-canary\n' >"${service_root}/var/lib/pgw/pgw.db"
chmod 0640 "${service_root}/var/lib/pgw/pgw.db"
chown 65534:65534 "${service_root}/var/lib/pgw" "${service_root}/var/lib/pgw/pgw.db"
printf 'present\t/var/lib/pgw\n' >"${service_snapshot}/manifest"
/usr/bin/python3 -I "${ROOT}/deploy/snapshot_payload.py" capture \
    "${service_snapshot}" "${service_root}" "${fixture}/key" key.root.runtime "${helper}" \
    install.service.owner release.service.owner \
    "${service_snapshot}/key-sequences/key-sequence-$(printf '%s' key.root.runtime | sha256sum | awk '{print $1}').json"
/usr/bin/python3 -I "${ROOT}/deploy/snapshot_payload.py" verify "${service_snapshot}" "${fixture}/key" "${helper}"

# A root-owned file below a service-owned directory is exfiltration shaped
# and must remain rejected: the declared trusted ancestor owner is derived
# from the file's own uid (0), which does not own the service directory.
mixed_root="${fixture}/mixed-source"
mixed_snapshot="${fixture}/mixed-snapshot"
install -d -m 0700 "${mixed_root}/var/lib/pgw" "${mixed_snapshot}/key-sequences"
printf 'root-only-material\n' >"${mixed_root}/var/lib/pgw/root-secret"
chmod 0600 "${mixed_root}/var/lib/pgw/root-secret"
chown 65534:65534 "${mixed_root}/var/lib/pgw"
printf 'present\t/var/lib/pgw\n' >"${mixed_snapshot}/manifest"
set +e
/usr/bin/python3 -I "${ROOT}/deploy/snapshot_payload.py" capture \
    "${mixed_snapshot}" "${mixed_root}" "${fixture}/key" key.root.runtime "${helper}" \
    install.mixed.owner release.mixed.owner \
    "${mixed_snapshot}/key-sequences/key-sequence-$(printf '%s' key.root.runtime | sha256sum | awk '{print $1}').json" \
    >/dev/null 2>&1
mixed_rc=$?
set -e
((mixed_rc != 0))
[[ ! -e "${mixed_snapshot}/payload.manifest.json" ]]

# Wrong-key verification must fail before a private plaintext stage exists.
printf 'abcdef0123456789abcdef0123456789' >"${fixture}/wrong-key"
chmod 0600 "${fixture}/wrong-key"
set +e
/usr/bin/python3 -I "${ROOT}/deploy/snapshot_payload.py" materialize \
    "${snapshot}" "${fixture}/wrong-key" "${helper}" "${fixture}/wrong-stage" >/dev/null 2>&1
wrong_rc=$?
set -e
((wrong_rc != 0))
[[ ! -e "${fixture}/wrong-stage" ]]

/usr/bin/python3 -I "${ROOT}/deploy/snapshot_payload.py" materialize \
    "${snapshot}" "${fixture}/key" "${helper}" "${stage}"
[[ "$(stat -c '%u:%a:%F' "${stage}")" == '0:700:directory' ]]
[[ "$(<"${stage}/files/var/lib/pgw/pgw.db")" == root-runtime-canary ]]
/usr/bin/python3 -I "${ROOT}/deploy/restore_snapshot.py" metadata "${stage}"
/usr/bin/python3 -I "${ROOT}/deploy/restore_snapshot.py" present \
    "${stage}/files/var/lib/pgw" "${host_root}/var/lib/pgw" \
    "${stage}/metadata.json" /var/lib/pgw 0
[[ "$(<"${host_root}/var/lib/pgw/pgw.db")" == root-runtime-canary ]]
/usr/bin/python3 -I "${ROOT}/deploy/snapshot_payload.py" remove-stage "${stage}" 0
[[ ! -e "${stage}" ]]

# Recovery derives an exact legacy-sealed stage and invokes this same
# descriptor-bound remove-stage primitive with expected uid 0. A foreign-owned
# private-stage-shaped target must fail closed; its exact path and a sibling
# canary must remain, proving no broad /run cleanup can occur.
foreign_stage="${fixture}/legacy-sealed.install.foreign"
foreign_canary="${fixture}/legacy-sealed.not-snapshot"
install -d -m 0700 "${foreign_stage}/files" "${foreign_canary}"
chown -R 65534:65534 "${foreign_stage}"
set +e
/usr/bin/python3 -I "${ROOT}/deploy/snapshot_payload.py" remove-stage "${foreign_stage}" 0 >/dev/null 2>&1
foreign_rc=$?
set -e
((foreign_rc != 0))
[[ -d "${foreign_stage}" && -d "${foreign_canary}" ]]
# Restore only fixture ownership so the root-owned trap can clean it up.
chown -R 0:0 "${foreign_stage}"

# Journal recovery calls the same exact report-runtime primitive. Prove that a
# foreign-owned directory and a foreign-owned report both fail closed without
# deleting their sibling canary.
for foreign_kind in runtime report; do
    foreign_parent="${fixture}/legacy-report-${foreign_kind}"
    foreign_runtime="${foreign_parent}/legacy-import"
    foreign_report_canary="${fixture}/legacy-report-canary-${foreign_kind}"
    install -d -m 0700 "${foreign_parent}" "${foreign_runtime}"
    printf 'report\n' >"${foreign_runtime}/report.json"
    chmod 0600 "${foreign_runtime}/report.json"
    printf 'sibling\n' >"${foreign_report_canary}"
    if [[ "${foreign_kind}" == runtime ]]; then
        chown 65534:65534 "${foreign_runtime}"
    else
        chown 65534:65534 "${foreign_runtime}/report.json"
    fi
    set +e
    /usr/bin/python3 -I "${ROOT}/deploy/snapshot_payload.py" remove-legacy-report \
        "${foreign_runtime}" 0 >/dev/null 2>&1
    foreign_report_rc=$?
    set -e
    ((foreign_report_rc != 0))
    [[ -d "${foreign_runtime}" && -e "${foreign_runtime}/report.json" && -f "${foreign_report_canary}" ]]
    chown 0:0 "${foreign_runtime}" "${foreign_runtime}/report.json"
done

printf 'snapshot payload Linux/root harness: PASS\n'
