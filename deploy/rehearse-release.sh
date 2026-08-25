#!/bin/bash
set -Eeuo pipefail

readonly SAFE_PATH="/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
PATH="${SAFE_PATH}"
export PATH

# This checkout/bundle entrypoint is deliberately non-root. Authenticated
# full-system evidence is produced only by a separately trusted VM runner; PR
# code is never promoted to uid 0 on the shared runner.
((EUID != 0)) || {
    printf 'nonroot fixture rehearsal refuses uid 0; use the authenticated disposable-VM runner for full-system evidence\n' >&2
    exit 96
}
(($# == 2)) || {
    printf 'usage: rehearse-release.sh ASSEMBLY OUTPUT_EVIDENCE_DIRECTORY\n' >&2
    exit 2
}
readonly REQUIRED_TOOLS=(awk cp dirname env find install mktemp readlink rm setpriv sha256sum stat tee tr)
for required_tool in "${REQUIRED_TOOLS[@]}"; do
    command -v "${required_tool}" >/dev/null 2>&1 || {
        printf 'missing nonroot rehearsal tool: %s\n' "${required_tool}" >&2
        exit 69
    }
done
python3_resolved="$(readlink -f -- /usr/bin/python3 2>/dev/null || true)"
[[ "${python3_resolved}" =~ ^/usr/bin/python3([.][0-9]+)*$ && -f "${python3_resolved}" &&
   ! -L /usr && ! -L /usr/bin &&
   "$(stat -c '%U:%G:%a' /usr /usr/bin "${python3_resolved}")" == $'root:root:755\nroot:root:755\nroot:root:755' ]] || {
    printf 'fixed Python interpreter unavailable for descriptor-first snapshot\n' >&2
    exit 69
}

assembly_input="$1"
output="$2"
[[ "${output}" == /* && ! -e "${output}" && ! -L "${output}" ]] || {
    printf 'evidence output must be a new absolute path\n' >&2
    exit 2
}
output_parent="$(dirname -- "${output}")"
[[ -d "${output_parent}" && ! -L "${output_parent}" ]] || {
    printf 'evidence output parent must be an existing non-symlink directory\n' >&2
    exit 2
}
output_parent="$(readlink -f -- "${output_parent}")"
output_name="$(basename -- "${output}")"
[[ "${output_name}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] || {
    printf 'invalid evidence output directory name\n' >&2
    exit 2
}
output="${output_parent}/${output_name}"

bootstrap_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
snapshot_helper="${bootstrap_root}/deploy/tests/release_snapshot.py"
[[ -f "${snapshot_helper}" && ! -L "${snapshot_helper}" ]] || {
    printf 'descriptor-first snapshot helper is unavailable\n' >&2
    exit 65
}
case "${output_parent}/" in
    "${bootstrap_root}/"*)
        printf 'rehearsal output cannot be nested in the checkout\n' >&2
        exit 65
        ;;
esac
assembly_compare="$(readlink -f -- "${assembly_input}" 2>/dev/null || true)"
if [[ -n "${assembly_compare}" ]]; then
    case "${output_parent}/" in
        "${assembly_compare}/"*)
            printf 'rehearsal output cannot be nested in the assembly\n' >&2
            exit 65
            ;;
    esac
fi

work="$(mktemp -d "${output_parent}/.pgw-rehearsal-work.XXXXXXXX")"
stage="$(mktemp -d "${output_parent}/.pgw-rehearsal-evidence.XXXXXXXX")"
snapshot="${work}/assembly"
cleanup() {
    [[ "${work}" == "${output_parent}/.pgw-rehearsal-work."* ]] && rm -rf -- "${work}"
    [[ "${stage}" == "${output_parent}/.pgw-rehearsal-evidence."* ]] && rm -rf -- "${stage}"
}
trap cleanup EXIT
chmod 0700 "${work}" "${stage}"

# Open every source component without following symlinks, reject special nodes,
# copy through stable descriptors, then parse only the private snapshot.
/usr/bin/python3 -I "${snapshot_helper}" snapshot "${assembly_input}" "${snapshot}"
/usr/bin/python3 -I "${snapshot}/release/deploy/tests/release_snapshot.py" verify "${snapshot}" \
    >"${stage}/assembly-verification.tsv"
release_id="$(awk -F '\t' '$1=="release_id" {print $2}' "${stage}/assembly-verification.tsv")"
release_manifest_sha256="$(awk -F '\t' '$1=="release_manifest_sha256" {print $2}' "${stage}/assembly-verification.tsv")"
[[ "${release_id}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ &&
   "${release_manifest_sha256}" =~ ^[0-9a-f]{64}$ &&
   "$(grep -c $'^binary\t' "${stage}/assembly-verification.tsv")" == 7 ]] || {
    printf 'strict assembly verification report is incomplete\n' >&2
    exit 65
}

cap_eff="$(awk '/^CapEff:/ {print $2}' /proc/self/status 2>/dev/null || true)"
no_new_privs="$(awk '/^NoNewPrivs:/ {print $2}' /proc/self/status 2>/dev/null || true)"
[[ -n "${cap_eff}" ]] || cap_eff=unknown
[[ -n "${no_new_privs}" ]] || no_new_privs=unknown
{
    printf 'transaction_model\tnonroot_fixture\n'
    printf 'uid\t%s\n' "${EUID}"
    printf 'gid\t%s\n' "$(id -g)"
    printf 'cap_eff\t%s\n' "${cap_eff}"
    printf 'no_new_privs_initial\t%s\n' "${no_new_privs}"
    for namespace in user pid mnt net ipc uts; do
        if [[ -e "/proc/self/ns/${namespace}" ]]; then
            printf 'namespace_%s\t%s\n' "${namespace}" "$(readlink -- "/proc/self/ns/${namespace}")"
        else
            printf 'namespace_%s\tunavailable\n' "${namespace}"
        fi
    done
    printf 'filesystem_boundary\tprivate_descriptor_snapshot_and_fixture_root\n'
    printf 'external_effects\tsystemd,nft,sysctl,accounts,openssl,service-db-start:fixture_adapters\n'
} >"${stage}/isolation-identity.tsv"

exec 3>&1 4>&2
exec > >(tee "${stage}/rehearsal.transcript") 2>&1
printf 'PGW nonroot transaction-model rehearsal\n'
printf 'release_id=%s manifest_sha256=%s\n' "${release_id}" "${release_manifest_sha256}"
printf 'transaction_model=nonroot_fixture production_gate=FAIL full_system_authenticated=false\n'
printf 'harness_provenance=release_manifest snapshot=descriptor_first\n'

set +e
# --bounding-set=-all requires CAP_SETPCAP, which this already-unprivileged
# caller (line 11 rejects EUID 0) does not hold. Gaining it via a user
# namespace would need setpriv to then drop back from namespace-root to
# this caller's real uid so installer_harness.sh's own EUID-0 rejection
# still holds downstream - but that uid isn't a valid mapped id inside a
# --map-root-user namespace (its uid_map has exactly one entry: 0 <-> our
# real uid), so setpriv's own reuid there fails too. Unlike
# nonroot_crash_evidence_runner.sh (dropping from real root, where this
# is a full capability-zero proof), this rehearsal's own bounding set
# starts empty as a normal unprivileged process; clearing the inheritable
# and ambient sets (which don't need CAP_SETPCAP) already prevents any of
# it from surviving into the child regardless.
setpriv --no-new-privs --inh-caps=-all --ambient-caps=-all \
    env -i PATH="${SAFE_PATH}" LANG=C LC_ALL=C HOME="${work}" TMPDIR="${work}" \
    PGW_TRANSACTION_SECTION=all PGW_TRANSACTION_EVIDENCE_DIR="${stage}" \
    PGW_TRANSACTION_TEMP_PARENT="${work}" \
    /bin/bash "${snapshot}/release/deploy/tests/installer_transaction_test.sh"
transaction_rc=$?
set -e
printf 'transaction_suite_rc=%s\n' "${transaction_rc}"
((transaction_rc == 0)) || exit "${transaction_rc}"

for required_result in fixture_upgrade fixture_rollback fixture_fail_close; do
    grep -Fxq "${required_result} PASS" "${stage}/fixture-results.manifest" || {
        printf 'missing fixture result: %s\n' "${required_result}" >&2
        exit 65
    }
done
for required_phase in after_accounts after_binaries after_ui_assets after_credentials \
    after_units after_firewall after_services; do
    [[ "$(awk -F '\t' -v phase="${required_phase}" \
        '$1==phase && $2=="production_function" && $3=="fixture_adapters" && $7==0 && $10=="nonroot_fixture" {count++} END {print count+0}' \
        "${stage}/lifecycle-transcript.tsv")" == 1 ]] || {
        printf 'missing exact successful lifecycle phase: %s\n' "${required_phase}" >&2
        exit 65
    }
done
printf 'fixture_transaction_model PASS; production promotion remains blocked\n'

cat >"${stage}/rehearsal.manifest" <<EOF
format pgw-rehearsal-v2
release_id ${release_id}
release_manifest_sha256 ${release_manifest_sha256}
transaction_model nonroot_fixture
isolation nonroot,no-new-privileges,capability-free,descriptor-snapshot,filesystem-fixture
harness_provenance release_manifest
fixture_upgrade PASS
fixture_rollback PASS
fixture_fail_close PASS
production_root_lifecycle NOT_RUN
database_service_migration MODELED_EXTERNAL_EFFECT
full_system_authenticated false
production_gate FAIL
EOF

exec 1>&3 2>&4
exec 3>&- 4>&-
wait
find "${stage}" -maxdepth 1 -type f -exec chmod 0644 {} +
rm -rf -- "${snapshot}"
mv -T -- "${stage}" "${output}"
trap - EXIT
rm -rf -- "${work}"
