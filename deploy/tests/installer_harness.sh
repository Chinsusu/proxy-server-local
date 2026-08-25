#!/bin/bash
readonly HARNESS_SAFE_PATH="/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
PATH="${HARNESS_SAFE_PATH}"
export PATH
set -Eeuo pipefail

((EUID != 0)) || { printf 'installer harness must run non-root\n' >&2; exit 96; }
(($# == 4)) || { printf 'usage: installer_harness.sh FIXTURE BOUNDARY RESTORE_FAILURE ARTIFACT_ROOT\n' >&2; exit 2; }

fixture="$(cd -- "$1" && pwd -P)"
boundary="$2"
restore_failure="$3"
[[ "$4" == /* && -d "$4" && ! -L "$4" ]] \
    || { printf 'unsafe harness artifact root\n' >&2; exit 2; }
artifact_root="$(cd -- "$4" && pwd -P)"
[[ "${artifact_root}" == "$4" && "$(stat -c '%u:%a:%F' "${artifact_root}")" == "${EUID}:700:directory" ]] \
    || { printf 'unsafe harness artifact root\n' >&2; exit 2; }
transaction_root="$(dirname -- "${fixture}")"
[[ "${artifact_root}" == "${transaction_root}/release-artifacts" && ! -L "${transaction_root}" &&
   "$(stat -c '%u:%a:%F' "${transaction_root}")" == "${EUID}:700:directory" ]] \
    || { printf 'harness artifacts are outside the private transaction root\n' >&2; exit 2; }
artifact_count=0
while IFS= read -r -d '' artifact; do
    artifact_name="$(basename -- "${artifact}")"
    case "${artifact_name}" in
        pgw-api|pgw-agent|pgw-fwd|pgw-ui|pgw-health|pgw-snapshot-crypt) ;;
        *) printf 'unexpected harness artifact: %s\n' "${artifact_name}" >&2; exit 2 ;;
    esac
    [[ -f "${artifact}" && ! -L "${artifact}" &&
       "$(stat -c '%u:%a:%F:%h' "${artifact}")" == "${EUID}:555:regular file:1" ]] \
        || { printf 'unsafe harness artifact: %s\n' "${artifact_name}" >&2; exit 2; }
    ((artifact_count++)) || true
done < <(find "${artifact_root}" -mindepth 1 -maxdepth 1 -print0)
((artifact_count == 6)) || { printf 'incomplete harness artifact set\n' >&2; exit 2; }
readonly artifact_root
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"

export PGW_INSTALL_INTERNAL_SOURCE=pgw-nonroot-lifecycle-test-v1
export PGW_INTERNAL_TEST_MARKER="${fixture}/.pgw-installer-source-marker"
export PGW_INTERNAL_PYTHON_BINARY="${fixture}/fake-bin/python3"
export PGW_INSTALL_TEST_ROOT="${fixture}"
export PGW_INSTALL_TEST_COMMAND="${fixture}/fake-bin/lifecycle"
export PGW_INSTALL_SYSTEM_ROOT="${fixture}/system"
export PGW_INSTALL_BACKUP_ROOT="${fixture}/backups"
export PGW_FAKE_ROOT="${fixture}"
export PGW_FAIL_AT="${boundary}"
export PGW_RESTORE_FAIL_AT="${restore_failure}"

# shellcheck source=../install-pgw.sh
source "${root}/deploy/install-pgw.sh"

# Crash evidence wraps production functions only inside the validated non-root
# harness.  The root installer has no crash/test environment or executable hook.
eval "$(declare -f release_file | sed '1s/^release_file /production_release_file /')"
eval "$(declare -f force_forwarding_off | sed '1s/^force_forwarding_off /production_force_forwarding_off /')"
eval "$(declare -f capture_snapshot_payload | sed '1s/^capture_snapshot_payload /production_capture_snapshot_payload /')"
eval "$(declare -f write_recovery_journal | sed '1s/^write_recovery_journal /production_write_recovery_journal /')"
eval "$(declare -f execute_install_phase | sed '1s/^execute_install_phase /production_execute_install_phase /')"
release_file() {
    local relative="$1" artifact
    case "${relative}" in
        artifacts/pgw-api|artifacts/pgw-agent|artifacts/pgw-fwd|artifacts/pgw-ui|artifacts/pgw-health|artifacts/pgw-snapshot-crypt)
            artifact="${artifact_root}/${relative#artifacts/}"
            [[ -f "${artifact}" && ! -L "${artifact}" &&
               "$(stat -c '%u:%a:%F:%h' "${artifact}")" == "${EUID}:555:regular file:1" ]] \
                || die "unsafe test-only release artifact: ${relative}"
            printf '%s\n' "${artifact}"
            ;;
        *) production_release_file "${relative}" ;;
    esac
}
capture_crash_fired=0
force_forwarding_off() {
    if [[ "${boundary}" == crash_capture:journal && "${capture_crash_fired}" == 0 ]]; then
        capture_crash_fired=1
        kill -KILL "$$"
    fi
    production_force_forwarding_off "$@"
}
capture_snapshot_payload() {
    if [[ "${boundary}" == crash_capture:quiesced ]]; then
        kill -KILL "$$"
    fi
    production_capture_snapshot_payload "$@"
    if [[ "${boundary}" == crash_capture:payload ]]; then
        kill -KILL "$$"
    fi
}
write_recovery_journal() {
    if [[ "${boundary}" == crash_capture:sealed && "${1:-}" == ready ]]; then
        kill -KILL "$$"
    fi
    production_write_recovery_journal "$@"
}
# Fakes are reachable only after the production library has validated a
# non-root source context. Executing install-pgw.sh always rejects these vars.
PATH="${fixture}/fake-bin:${PGW_HARNESS_TEST_PATH:-${HARNESS_SAFE_PATH}}"
export PATH
lan_address=192.0.2.10

failure_point() {
    if [[ "${boundary}" == crash_legacy_post_import && "$1" == legacy_importer_success ]]; then
        kill -KILL "$$"
    fi
    if [[ "${PGW_FAIL_AT}" == "$1" ]]; then
        if ! grep -Fxq "forwarding-closed-before:$1" "${fixture}/wan-sentinel.log" 2>/dev/null; then
            [[ "$(tr -d '[:space:]' <"${fixture}/runtime/ip-forward")" == 0 ]] || {
                printf 'forwarding-open-before:%s\n' "$1" >>"${fixture}/wan-sentinel.log"
                die "IPv4 forwarding was open at failure boundary $1"
            }
            printf 'forwarding-closed-before:%s\n' "$1" >>"${fixture}/wan-sentinel.log"
        fi
        die "injected failure at $1"
    fi
}
restore_failure_point() {
    [[ "${PGW_RESTORE_FAIL_AT}" != "$1" ]] || die "injected rollback failure at $1"
}
fixture_state() {
    local mode="$1"
    case "${mode}" in
        bytes)
            find "${fixture}/system" "${fixture}/runtime" -xdev -type f -printf '%s\n' \
                | awk '{total += $1} END {printf "%d", total + 0}'
            ;;
        sha256)
            (
                cd -- "${fixture}"
                while IFS= read -r -d '' path; do
                    printf '%s\0' "${path}"
                    if [[ -L "${path}" ]]; then
                        printf 'link\0%s\0' "$(readlink -- "${path}")"
                    elif [[ -f "${path}" ]]; then
                        printf 'file\0%s\0%s\0' "$(stat -c '%a' -- "${path}")" \
                            "$(sha256sum -- "${path}" | awk '{print $1}')"
                    elif [[ -d "${path}" ]]; then
                        printf 'directory\0%s\0' "$(stat -c '%a' -- "${path}")"
                    else
                        printf 'special\0'
                    fi
                done < <(find system runtime -xdev -mindepth 1 -print0 | LC_ALL=C sort -z)
            ) | sha256sum | awk '{print $1}'
            ;;
        *) die "invalid fixture state request" ;;
    esac
}

execute_install_phase() {
    local phase="$1" before_sha before_bytes after_sha after_bytes rc cap_eff
    if ! grep -Fxq "forwarding-closed-before:${phase}" "${fixture}/wan-sentinel.log" 2>/dev/null; then
        [[ "$(tr -d '[:space:]' <"${fixture}/runtime/ip-forward")" == 0 ]] || {
            printf 'forwarding-open-before:%s\n' "${phase}" >>"${fixture}/wan-sentinel.log"
            die "IPv4 forwarding was open before production phase ${phase}"
        }
        printf 'forwarding-closed-before:%s\n' "${phase}" >>"${fixture}/wan-sentinel.log"
    fi
    before_sha="$(fixture_state sha256)"
    before_bytes="$(fixture_state bytes)"
    cap_eff="$(awk '/^CapEff:/ {print $2}' /proc/self/status 2>/dev/null || true)"
    [[ -n "${cap_eff}" ]] || cap_eff=unknown
    set +e
    ( set -Eeuo pipefail; production_execute_install_phase "${phase}" )
    rc=$?
    set -e
    after_sha="$(fixture_state sha256)"
    after_bytes="$(fixture_state bytes)"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "${phase}" production_function fixture_adapters "${EUID}" "$(id -g)" \
        "${cap_eff}" "${rc}" "${before_sha}:${before_bytes}" "${after_sha}:${after_bytes}" \
        nonroot_fixture >>"${fixture}/lifecycle-transcript.tsv"
    return "${rc}"
}

trap on_exit EXIT
prepare_lifecycle_roots
printf 'phase\texecution\texternal_effects\tuid\tgid\tcap_eff\trc\tbefore_sha256_bytes\tafter_sha256_bytes\ttransaction_model\n' \
    >"${fixture}/lifecycle-transcript.tsv"
if [[ "${boundary}" == recover ]]; then
    recover_interrupted_lifecycle
    trap - EXIT
    exit 0
fi
if [[ "${boundary}" == recover_restore_crash ]]; then
    rm -f -- "${fixture}/restore-crash-control"
    recover_interrupted_lifecycle
    trap - EXIT
    exit 0
fi
if [[ "${boundary}" == crash_legacy_sealed ]]; then
    # lifecycle_fake kills immediately after production materialization and
    # before the sealed plaintext can be consumed or removed.
    legacy_state_pending=1
    legacy_state_checksum="$(printf '0%.0s' {1..64})"
    export PGW_CRASH_LEGACY_SEALED=1
fi
capture_state
if [[ "${boundary}" == crash_capture:* ]]; then
    die "capture crash injector returned unexpectedly"
fi
if [[ "${boundary}" == restore_crash:* ]]; then
    IFS=: read -r _ crash_state crash_point <<<"${boundary}"
    [[ ! -e "${fixture}/restore-hook-reached.json" ]] || die "stale restore hook marker"
    case "${crash_state}" in
        present)
            crash_logical=/var/lib/pgw
            printf 'mutated-db\n' >"${fixture}/system/var/lib/pgw/pgw.db"
            printf 'mutated-nested\n' >"${fixture}/system/var/lib/pgw/nested/one"
            cp -a -- "${fixture}/system/var/lib/pgw" "${fixture}/precrash-target"
            ;;
        absent)
            crash_logical=/etc/pgw/credential-inbox
            install -d "${fixture}/system/etc/pgw/credential-inbox/nested"
            printf 'ephemeral-secret-a\n' >"${fixture}/system/etc/pgw/credential-inbox/secret-a"
            printf 'ephemeral-secret-b\n' >"${fixture}/system/etc/pgw/credential-inbox/nested/secret-b"
            cp -a -- "${fixture}/system/etc/pgw/credential-inbox" "${fixture}/precrash-target"
            ;;
        *) die "invalid restore crash state" ;;
    esac
    crash_nonce="$(printf '%s\0%s\0%s' "${fixture}" "${crash_state}" "${crash_point}" \
        | sha256sum | awk '{print $1}')"
    # Production journals the HMAC-covered ciphertext manifest identity.  The
    # transient /run stage metadata has a different identity and must not
    # become authority for recovery, so give the test-only crash shim the
    # same pre-stage identifier that production recorded.
    crash_operation_id="$(restore_operation_id "${crash_state}" "${crash_logical}")"
    [[ "${crash_operation_id}" =~ ^[0-9a-f]{64}$ ]] || die "invalid crash operation id"
    printf '%s\t%s\t%s\t%s\t%s\n' \
        "${crash_state}" "${crash_logical}" "${crash_point}" "${crash_nonce}" "${crash_operation_id}" \
        >"${fixture}/restore-crash-control"
    printf '1\n' >"${fixture}/runtime/ip-forward"
    restore_snapshot
    die "restore crash injector returned unexpectedly"
fi
if [[ "${boundary}" == crash_ready ]]; then
    "${PGW_INSTALL_TEST_COMMAND}" mutate "${fixture}" "${backup_dir}" after_credentials
    trap - EXIT
    exit 99
fi
if [[ "${boundary}" == tamper_snapshot ]]; then
    printf 'tampered\n' >>"${backup_dir}/snapshot.sha256"
    validate_rollback_snapshot "${backup_dir}"
fi
run_install_transaction
if [[ "${boundary}" == success_rollback ]]; then
    [[ "$(tr -d '[:space:]' <"${fixture}/runtime/ip-forward")" == 1 ]] \
        || die "successful upgrade did not restore forwarding"
    for installed_command in api agent fwd ui health; do
        [[ -f "${fixture}/system/usr/local/bin/pgw-${installed_command}" ]] &&
            cmp -s "${fixture}/system/usr/local/bin/pgw-${installed_command}" \
                "$(release_file "artifacts/pgw-${installed_command}")" \
            || die "successful upgrade did not publish pgw-${installed_command}"
    done
    for deployed_file in \
        deploy/sysusers.d/pgw.conf:/etc/sysusers.d/pgw.conf \
        deploy/tmpfiles.d/pgw.conf:/etc/tmpfiles.d/pgw.conf \
        deploy/polkit-1/rules.d/50-pgw-agent-forwarder.rules:/etc/polkit-1/rules.d/50-pgw-agent-forwarder.rules \
        deploy/systemd/pgw-api.service:/etc/systemd/system/pgw-api.service \
        deploy/systemd/pgw-agent.service:/etc/systemd/system/pgw-agent.service \
        deploy/systemd/pgw-fwd@.service:/etc/systemd/system/pgw-fwd@.service \
        deploy/systemd/pgw-ui.service:/etc/systemd/system/pgw-ui.service \
        deploy/systemd/pgw-health.service:/etc/systemd/system/pgw-health.service \
        deploy/systemd/nftables.service.d/pgw.conf:/etc/systemd/system/nftables.service.d/pgw.conf \
        deploy/systemd/systemd-sysctl.service.d/pgw.conf:/etc/systemd/system/systemd-sysctl.service.d/pgw.conf \
        deploy/nftables.conf:/etc/nftables.conf \
        deploy/sysctl-pgw.conf:/etc/sysctl.d/99-pgw.conf; do
        source_relative="${deployed_file%%:*}"
        deployed_logical="${deployed_file#*:}"
        cmp -s "$(release_file "${source_relative}")" "$(host_path "${deployed_logical}")" \
            || die "production phase did not publish ${deployed_logical}"
    done
    (cd -- "${UI_ROOT}" && sha256sum -c .manifest.sha256 >/dev/null) \
        || die "production UI asset publication did not verify"
    [[ -L "$(host_path /etc/pgw/credentials-current)" &&
       ! -e "$(host_path /etc/pgw/ui.crt)" && ! -e "$(host_path /etc/pgw/ui.key)" &&
       ! -e "$(host_path /etc/pgw/ui_proxy_token)" ]] \
        || die "legacy UI credentials were not atomically transitioned"
    grep -Fxq 'PGW_LAN_ADDRESS=192.0.2.10' "$(host_path /etc/pgw/pgw.env)" \
        || die "production config phase did not publish fixture LAN address"
    [[ "$(sqlite3 "$(host_path /var/lib/pgw/pgw.db)" 'PRAGMA integrity_check;')" == ok ]] \
        || die "fixture SQLite integrity adapter failed"
    printf 'database_migration\tservice_start_adapter\tnot_full_system\n' \
        >>"${fixture}/validation-transcript.tsv"
    for completed_phase in after_accounts after_binaries after_ui_assets after_credentials \
        after_legacy_import after_units after_firewall after_services; do
        [[ "$(grep -Fxc "forwarding-closed-before:${completed_phase}" "${fixture}/wan-sentinel.log")" == 1 ]] \
            || die "missing exact fail-close phase evidence: ${completed_phase}"
    done
    ! grep -Fq 'forwarding-open-before:' "${fixture}/wan-sentinel.log" \
        || die "forwarding opened before an install phase"
    printf 'fixture_upgrade PASS\n' >>"${fixture}/rehearsal-results"
    clear_recovery_journal
    validate_rollback_snapshot "${backup_dir}"
    printf 'manual-rollback-begin\n' >>"${fixture}/commands.log"
    restore_snapshot
    rollback_marker_line="$(grep -nF 'manual-rollback-begin' "${fixture}/commands.log" | tail -n1 | cut -d: -f1)"
    rollback_first_command="$(sed -n "$((rollback_marker_line + 1))p" "${fixture}/commands.log")"
    rollback_first_restore_line="$(grep -nE 'python3 .*restore_snapshot[.]py (present|absent) ' \
        "${fixture}/commands.log" | awk -F: -v marker="${rollback_marker_line}" '$1>marker {print $1; exit}')"
    if [[ "${rollback_first_command}" != 'sysctl -q -w net.ipv4.ip_forward=0' ||
          -z "${rollback_first_restore_line}" || "${rollback_first_restore_line}" -le "${rollback_marker_line}" ]]; then
        printf '%s\n' '--- rollback command trace ---' >&2
        tail -n 120 "${fixture}/commands.log" >&2
        die "rollback did not force forwarding off before runtime mutation"
    fi
    diff -r --no-dereference "${fixture}/expected-system" "${fixture}/system"
    diff -r --no-dereference "${fixture}/expected-runtime" "${fixture}/runtime"
    printf 'fixture_rollback PASS\nfixture_fail_close PASS\n' >>"${fixture}/rehearsal-results"
fi
mutated=0
