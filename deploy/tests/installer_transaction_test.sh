#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
readonly ROOT
case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*)
        printf 'installer transaction tests: SKIP (Linux secure filesystem semantics required)\n'
        exit 0
        ;;
esac
readonly BOUNDARIES=(after_snapshot after_accounts after_binaries after_ui_assets after_credentials after_legacy_import after_units after_firewall after_services)
readonly RESTORE_FAILURES=(quiesce daemon_reload copy runtime_apply)
section="${PGW_TRANSACTION_SECTION:-all}"
evidence_dir="${PGW_TRANSACTION_EVIDENCE_DIR:-}"
[[ "${section}" == all || "${section}" == boundaries || "${section}" == restore || \
   "${section}" == crash || "${section}" == capture-crash || \
   "${section}" == restore-crash || "${section}" == tamper || "${section}" == success ]] \
    || { printf 'invalid PGW_TRANSACTION_SECTION\n' >&2; exit 2; }

temp_parent="${PGW_TRANSACTION_TEMP_PARENT:-${ROOT}}"
[[ "${temp_parent}" == /* && -d "${temp_parent}" && ! -L "${temp_parent}" &&
   "$(stat -c '%u' "${temp_parent}")" == "${EUID}" &&
   $((8#$(stat -c '%a' "${temp_parent}") & 8#022)) == 0 ]] || {
    printf 'unsafe transaction fixture parent\n' >&2
    exit 2
}
temp_root="$(mktemp -d "${temp_parent}/.pgw-transaction.XXXXXXXX")"
# Failure evidence must not leave a credential-bearing transaction workspace
# in the source checkout. Tests print their phase-specific logs before exit;
# the fixture and its test-only release artifacts are always removed together.
artifact_root="${temp_root}/release-artifacts"
cleanup() {
    rm -rf -- "${temp_root}"
}
trap cleanup EXIT

# The production release builder creates these artifacts after source
# admission. Build the same binaries below the already-private transaction
# root, never below the repository release tree consumed by production.
install -d -m 0700 "${artifact_root}"
for command_name in api agent fwd ui health snapshot-crypt; do
    artifact="${artifact_root}/pgw-${command_name}"
    CGO_ENABLED=0 go build -trimpath -buildvcs=false -o "${artifact}" "./cmd/${command_name}"
    chmod 0555 "${artifact}"
done

make_fixture() {
    local fixture="$1" mode="${2:-active}" system fake parent parent_mode parent_uid
    local -a managed_absent_parents
    system="${fixture}/system"
    managed_absent_parents=(
        "${system}/etc/pgw"
        "${system}/etc/nftables.d"
        "${system}/etc/sysctl.d"
        "${system}/etc/sysusers.d"
        "${system}/etc/tmpfiles.d"
        "${system}/etc/polkit-1/rules.d"
        "${system}/etc/sudoers.d"
        "${system}/etc/systemd/system"
        "${system}/etc/systemd/system/nftables.service.d"
        "${system}/etc/systemd/system/systemd-sysctl.service.d"
        "${system}/run/pgw"
    )
    install -d \
        "${system}/var/lib/pgw/rules" "${system}/var/lib/pgw-lifecycle" "${system}/etc/pgw" \
        "${system}/run/pgw/control" "${system}/run/pgw/forwarders/15001/credentials" \
        "${system}/usr/local/bin" "${system}/usr/local/sbin" \
        "${system}/usr/local/share/pgw/web/static" "${system}/proc" \
        "${fixture}/runtime" "${fixture}/fake-bin" "${fixture}/backups"
    install -d -m 0755 "${managed_absent_parents[@]}"
    for parent in "${managed_absent_parents[@]}"; do
        parent_uid="$(stat -c '%u' "${parent}")"
        parent_mode="$(stat -c '%a' "${parent}")"
        [[ "${parent_uid}" == "${EUID}" && ! -L "${parent}" && -d "${parent}" && \
           $((8#${parent_mode} & 8#022)) == 0 ]] || {
            printf 'unsafe managed restore parent fixture: %s\n' "${parent}" >&2
            return 1
        }
    done
    printf 'pgw-installer-test-v1\n' >"${fixture}/.pgw-installer-test"
    printf 'pgw-installer-nonroot-test-v1\n' >"${fixture}/.pgw-installer-source-marker"
    for fake in systemctl systemd-sysusers systemd-tmpfiles nft sysctl sqlite3 \
        python3 readlink openssl curl stat install chown lifecycle; do
        cp "${ROOT}/deploy/tests/lifecycle_fake.sh" "${fixture}/fake-bin/${fake}"
        chmod 0700 "${fixture}/fake-bin/${fake}" 2>/dev/null || true
    done
    printf 'old-db\n' >"${system}/var/lib/pgw/pgw.db"
    printf 'old-lkg\n' >"${system}/var/lib/pgw/rules/lkg.nft"
    install -d "${system}/var/lib/pgw/nested"
    printf 'old-nested-one\n' >"${system}/var/lib/pgw/nested/one"
    printf 'old-nested-two\n' >"${system}/var/lib/pgw/nested/two"
    printf 'old-uds\n' >"${system}/run/pgw/control/api-agent.sock"
    printf 'old-forwarder-config\n' >"${system}/run/pgw/forwarders/15001/forwarder.json"
    printf 'old-secret\n' >"${system}/run/pgw/forwarders/15001/credentials/proxy_password"
    for fake in api agent fwd ui health; do printf 'old-%s\n' "${fake}" >"${system}/usr/local/bin/pgw-${fake}"; done
    printf 'old-installer\n' >"${system}/usr/local/sbin/pgw-install-base"
    printf 'old-ui-asset\n' >"${system}/usr/local/share/pgw/web/static/app.js"
    printf 'old-ui-style\n' >"${system}/usr/local/share/pgw/web/static/styles.css"
    printf 'old-login\n' >"${system}/usr/local/share/pgw/web/static/login.js"
    printf 'old-layout\n' >"${system}/usr/local/share/pgw/web/static/layout.css"
    printf 'fixture-cert\n' >"${system}/etc/pgw/ui.crt"
    printf 'fixture-private-key\n' >"${system}/etc/pgw/ui.key"
    printf 'fixture-ui-proxy-token-0000000000000000000000000000000000000000\n' \
        >"${system}/etc/pgw/ui_proxy_token"
    printf '%s\n' '$argon2id$v=19$m=65536,t=3,p=2$Zml4dHVyZXNhbHQ$Zml4dHVyZWhhc2hmaXh0dXJlaGFzaA' \
        >"${system}/etc/pgw/admin_pass_hash"
    chmod 0600 "${system}/etc/pgw/ui.crt" "${system}/etc/pgw/ui.key" \
        "${system}/etc/pgw/ui_proxy_token" "${system}/etc/pgw/admin_pass_hash"
    printf '0123456789abcdef0123456789abcdef' >"${system}/etc/pgw/snapshot.hmac"
    printf '0123456789abcdef0123456789abcdef' >"${system}/etc/pgw/snapshot-encryption.key"
    printf 'key.fixture\n' >"${system}/etc/pgw/snapshot-encryption.key.id"
    chmod 0600 "${system}/etc/pgw/snapshot.hmac" 2>/dev/null || true
    chmod 0600 "${system}/etc/pgw/snapshot-encryption.key" \
        "${system}/etc/pgw/snapshot-encryption.key.id" 2>/dev/null || true

    if [[ "${mode}" == inactive ]]; then
        printf 'nftables.service\tdisabled\tinactive\t1\n' >"${fixture}/runtime/services"
        printf 'systemd-sysctl.service\tstatic\tinactive\t2\n' >>"${fixture}/runtime/services"
    else
        printf 'nftables.service\tenabled\tactive\t1\n' >"${fixture}/runtime/services"
        printf 'systemd-sysctl.service\tstatic\tactive\t2\n' >>"${fixture}/runtime/services"
    fi
    printf 'pgw-api.service\tenabled\tactive\t101\n' >>"${fixture}/runtime/services"
    printf 'pgw-agent.service\tenabled\tactive\t102\n' >>"${fixture}/runtime/services"
    printf 'pgw-ui.service\tenabled-runtime\tactive\t103\n' >>"${fixture}/runtime/services"
    printf 'pgw-health.service\tdisabled\tinactive\t104\n' >>"${fixture}/runtime/services"
    printf 'pgw-fwd@15001.service\tenabled\tactive\t105\n' >>"${fixture}/runtime/services"
    printf 'pgw-fwd@15002.service\tenabled-runtime\tinactive\t106\n' >>"${fixture}/runtime/services"
    printf 'table inet pgw_base { chain forward { type filter hook forward priority filter; policy drop; } }\n' >"${fixture}/runtime/ruleset.nft"
    if [[ "${mode}" == active ]]; then printf '1\n'; else printf '0\n'; fi >"${fixture}/runtime/ip-forward"
    for fake in 101:api 102:agent 103:ui 104:health 105:fwd 106:fwd; do
        install -d "${system}/proc/${fake%%:*}"
        rm -f -- "${system}/proc/${fake%%:*}/exe"
        ln -s "${system}/usr/local/bin/pgw-${fake#*:}" "${system}/proc/${fake%%:*}/exe"
    done
    # Production root can restore arbitrary authenticated ownership. This
    # non-root evidence fixture must instead use the caller's effective IDs so
    # decrypt-publish can reapply the captured metadata without privilege.
    chgrp -hR "$(id -g)" "${system}" "${fixture}/runtime"
    if find "${system}" "${fixture}/runtime" -xdev \
        \( ! -uid "${EUID}" -o ! -gid "$(id -g)" \) -print -quit | grep -q .; then
        printf 'non-root transaction fixture has foreign ownership\n' >&2
        return 1
    fi
    cp -a -- "${system}" "${fixture}/expected-system"
    cp -a -- "${fixture}/runtime" "${fixture}/expected-runtime"
}

assert_restore_authority_contract() {
    local fixture="${temp_root}/restore-authority-contract" command web static external rc
    make_fixture "${fixture}" inactive
    command="${fixture}/fake-bin/lifecycle"
    web="${fixture}/system/usr/local/share/pgw/web"
    static="${web}/static"
    chmod 0550 "${web}" "${static}"
    PGW_FAKE_ROOT="${fixture}" "${command}" restore-authority "${web}"
    [[ "$(stat -c '%a' "${web}")" == 750 && "$(stat -c '%a' "${static}")" == 750 ]] \
        || { printf 'restore-authority did not grant caller-only directory write\n' >&2; exit 1; }

    chmod 0570 "${static}"
    set +e
    PGW_FAKE_ROOT="${fixture}" "${command}" restore-authority "${web}" >/dev/null 2>&1
    rc=$?
    set -e
    [[ "${rc}" != 0 ]] || { printf 'restore-authority accepted group-writable tree\n' >&2; exit 1; }
    chmod 0750 "${static}"

    external="${fixture}/external-ui-asset"
    printf 'external\n' >"${external}"
    rm -f -- "${static}/app.js"
    ln -s "${external}" "${static}/app.js"
    set +e
    PGW_FAKE_ROOT="${fixture}" "${command}" restore-authority "${web}" >/dev/null 2>&1
    rc=$?
    set -e
    [[ "${rc}" != 0 ]] || { printf 'restore-authority accepted UI symlink\n' >&2; exit 1; }
    rm -f -- "${static}/app.js"
    mkfifo "${static}/app.js"
    set +e
    PGW_FAKE_ROOT="${fixture}" "${command}" restore-authority "${web}" >/dev/null 2>&1
    rc=$?
    set -e
    [[ "${rc}" != 0 ]] || { printf 'restore-authority accepted special UI file\n' >&2; exit 1; }
    rm -f -- "${static}/app.js"
    printf 'old-ui-asset\n' >"${static}/app.js"
}

cleanup_nonroot_sealed_ui_case() {
    local original_rc="$1" fixture="$2" cleanup_rc=0
    trap - EXIT
    /usr/bin/python3 -I - "${temp_root}" "${fixture}" "${EUID}" <<'PY' || cleanup_rc=$?
import os
import shutil
import stat
import sys

temp_root, fixture, expected_text = sys.argv[1:]
expected = int(expected_text)
allowed = {"sealed-ui-materialize-success", "sealed-ui-materialize-failure"}
name = os.path.basename(fixture)
if (not os.path.isabs(temp_root) or os.path.normpath(temp_root) != temp_root or
        fixture != os.path.join(temp_root, name) or name not in allowed):
    raise SystemExit("unsafe sealed UI cleanup target")

flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
if not shutil.rmtree.avoids_symlink_attacks:
    raise SystemExit("symlink-safe sealed UI cleanup is unavailable")
temp_fd = os.open(temp_root, flags)
case_fd = -1
try:
    temp_info = os.fstat(temp_fd)
    if temp_info.st_uid != expected or stat.S_IMODE(temp_info.st_mode) & 0o022:
        raise SystemExit("unsafe sealed UI cleanup parent")
    case_fd = os.open(name, flags, dir_fd=temp_fd)
    case_info = os.fstat(case_fd)
    if case_info.st_uid != expected or stat.S_IMODE(case_info.st_mode) != 0o700:
        raise SystemExit("unsafe sealed UI cleanup case")

    def grant_owner_cleanup(components):
        descriptor = os.dup(case_fd)
        try:
            for component in components:
                try:
                    child = os.open(component, flags, dir_fd=descriptor)
                except FileNotFoundError:
                    return
                info = os.fstat(child)
                if info.st_uid != expected or stat.S_IMODE(info.st_mode) & 0o022:
                    os.close(child)
                    raise SystemExit("unsafe sealed UI cleanup directory")
                os.close(descriptor)
                descriptor = child
            info = os.fstat(descriptor)
            os.fchmod(descriptor, stat.S_IMODE(info.st_mode) | stat.S_IWUSR | stat.S_IXUSR)
        finally:
            os.close(descriptor)

    fixed = ("usr", "local", "share", "pgw", "web")
    for prefix in (("source",), ("stage", "files")):
        grant_owner_cleanup(prefix + fixed + ("static",))
        grant_owner_cleanup(prefix + fixed)
    named = os.stat(name, dir_fd=temp_fd, follow_symlinks=False)
    if (named.st_dev, named.st_ino) != (case_info.st_dev, case_info.st_ino):
        raise SystemExit("sealed UI cleanup case identity changed")
    os.close(case_fd)
    case_fd = -1
    shutil.rmtree(name, dir_fd=temp_fd)
    try:
        os.stat(name, dir_fd=temp_fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise SystemExit("sealed UI cleanup left residue")
    os.fsync(temp_fd)
finally:
    if case_fd >= 0:
        os.close(case_fd)
    os.close(temp_fd)
PY
    if ((cleanup_rc != 0)); then
        printf 'unsafe non-root sealed UI case cleanup\n' >&2
        ((original_rc != 0)) || original_rc="${cleanup_rc}"
    fi
    exit "${original_rc}"
}

run_nonroot_sealed_ui_materialize_case() (
    local name="$1" inject_failure="$2" fixture source snapshot stage key helper ledger_id asset
    set -e
    fixture="${temp_root}/sealed-ui-materialize-${name}"
    source="${fixture}/source"
    snapshot="${fixture}/snapshot"
    stage="${fixture}/stage"
    key="${fixture}/key"
    helper="${artifact_root}/pgw-snapshot-crypt"
    install -d -m 0700 "${fixture}"
    trap 'cleanup_nonroot_sealed_ui_case "$?" "${fixture}"' EXIT
    install -d -m 0700 "${snapshot}/key-sequences" \
        "${source}/usr/local/share/pgw/web/static"
    for asset in app.js layout.css login.js styles.css; do
        printf 'sealed-ui-%s\n' "${asset}" >"${source}/usr/local/share/pgw/web/static/${asset}"
    done
    printf 'sealed-ui-manifest\n' >"${source}/usr/local/share/pgw/web/.manifest.sha256"
    chmod 0440 "${source}/usr/local/share/pgw/web/.manifest.sha256" \
        "${source}/usr/local/share/pgw/web/static/"*
    chmod 0550 "${source}/usr/local/share/pgw/web" \
        "${source}/usr/local/share/pgw/web/static"
    chgrp -hR "$(id -g)" "${source}"
    printf '0123456789abcdef0123456789abcdef' >"${key}"
    chmod 0600 "${key}"
    printf 'present\t/usr/local/share/pgw/web\n' >"${snapshot}/manifest"
    ledger_id="$(printf '%s' key.nonroot.ui | sha256sum | awk '{print $1}')"
    /usr/bin/python3 -I "${ROOT}/deploy/snapshot_payload.py" capture \
        "${snapshot}" "${source}" "${key}" key.nonroot.ui "${helper}" \
        install.nonroot.ui release.nonroot.ui \
        "${snapshot}/key-sequences/key-sequence-${ledger_id}.json"
    /usr/bin/python3 -I "${ROOT}/deploy/snapshot_payload.py" materialize \
        "${snapshot}" "${key}" "${helper}" "${stage}"
    if [[ "${inject_failure}" == 1 ]]; then
        printf 'injected post-materialize cleanup failure\n' >&2
        exit 86
    fi
    [[ "$(stat -c '%u:%g:%a' "${stage}/files/usr/local/share/pgw/web")" == \
       "${EUID}:$(id -g):550" &&
       "$(stat -c '%u:%g:%a' "${stage}/files/usr/local/share/pgw/web/static")" == \
       "${EUID}:$(id -g):550" ]] \
        || { printf 'non-root materialize did not restore sealed UI directory metadata\n' >&2; exit 1; }
    [[ "$(stat -c '%u:%g:%a' "${stage}/files/usr/local/share/pgw/web/.manifest.sha256")" == \
       "${EUID}:$(id -g):440" ]] \
        || { printf 'non-root materialize did not restore sealed UI manifest metadata\n' >&2; exit 1; }
    cmp -s "${source}/usr/local/share/pgw/web/.manifest.sha256" \
        "${stage}/files/usr/local/share/pgw/web/.manifest.sha256" \
        || { printf 'non-root materialize did not restore sealed UI manifest content\n' >&2; exit 1; }
    for asset in app.js layout.css login.js styles.css; do
        [[ "$(stat -c '%u:%g:%a' "${stage}/files/usr/local/share/pgw/web/static/${asset}")" == \
           "${EUID}:$(id -g):440" ]] \
            || { printf 'non-root materialize did not restore sealed UI asset metadata\n' >&2; exit 1; }
        cmp -s "${source}/usr/local/share/pgw/web/static/${asset}" \
            "${stage}/files/usr/local/share/pgw/web/static/${asset}" \
            || { printf 'non-root materialize did not restore sealed UI content\n' >&2; exit 1; }
    done
)

assert_nonroot_sealed_ui_materialize() {
    local fixture rc
    fixture="${temp_root}/sealed-ui-materialize-success"
    run_nonroot_sealed_ui_materialize_case success 0
    [[ ! -e "${fixture}" && ! -L "${fixture}" ]] \
        || { printf 'successful sealed UI materialize left residue\n' >&2; exit 1; }
    fixture="${temp_root}/sealed-ui-materialize-failure"
    set +e
    run_nonroot_sealed_ui_materialize_case failure 1
    rc=$?
    set -e
    [[ "${rc}" == 86 ]] \
        || { printf 'post-materialize cleanup injection returned %s\n' "${rc}" >&2; exit 1; }
    [[ ! -e "${fixture}" && ! -L "${fixture}" ]] \
        || { printf 'failed sealed UI materialize left residue\n' >&2; exit 1; }
}

run_failure() {
    local fixture="$1" boundary="$2" restore_failure="${3:-}" rc
    set +e
    PGW_HARNESS_TEST_PATH="${PATH}" /bin/bash "${ROOT}/deploy/tests/installer_harness.sh" \
        "${fixture}" "${boundary}" "${restore_failure}" "${artifact_root}" \
        >"${fixture}/stdout.log" 2>"${fixture}/installer.log"
    rc=$?
    set -e
    printf '%s\n' "${rc}"
}

run_failure_low_fd() {
    local fixture="$1" boundary="$2" rc
    set +e
    (
        ulimit -n 40
        PGW_HARNESS_TEST_PATH="${PATH}" /bin/bash "${ROOT}/deploy/tests/installer_harness.sh" \
            "${fixture}" "${boundary}" "" "${artifact_root}" \
            >"${fixture}/stdout.log" 2>"${fixture}/installer.log"
    )
    rc=$?
    set -e
    printf '%s\n' "${rc}"
}

assert_restore_crash_phase() {
    local fixture="$1" snapshot="$2" state="$3" point="$4" logical="$5"
    local digest target parent residue_kind residue stage_root source_tree
    stage_root="${fixture}/system/run/pgw/snapshot-restore.$(basename -- "${snapshot}")"
    source_tree="${stage_root}/files/var/lib/pgw"
    digest="$({ cat "${stage_root}/metadata.json"; printf '\0%s' "${logical}"; } | sha256sum | awk '{print $1}')"
    target="${fixture}/system${logical}"
    parent="$(dirname -- "${target}")"
    [[ "${state}" == present ]] && residue_kind=stage || residue_kind=tomb
    residue="${parent}/.pgw-restore-${residue_kind}-${digest:0:24}"

    case "${state}:${point}" in
        present:partial_stage)
            [[ -d "${target}" && -d "${residue}" ]]
            [[ "$(<"${target}/pgw.db")" == mutated-db ]]
            ! diff -r --no-dereference "${source_tree}" "${residue}" >/dev/null
            find "${residue}" -mindepth 1 -print -quit | grep -q .
            ;;
        present:post_exchange)
            diff -r --no-dereference "${source_tree}" "${target}"
            diff -r --no-dereference "${fixture}/precrash-target" "${residue}"
            ;;
        present:mid_cleanup)
            diff -r --no-dereference "${source_tree}" "${target}"
            [[ -d "${residue}" ]]
            ! diff -r --no-dereference "${fixture}/precrash-target" "${residue}" >/dev/null
            find "${residue}" -mindepth 1 -print -quit | grep -q .
            ;;
        absent:partial_stage)
            diff -r --no-dereference "${fixture}/precrash-target" "${target}"
            [[ ! -e "${residue}" ]]
            ;;
        absent:post_exchange)
            [[ ! -e "${target}" ]]
            diff -r --no-dereference "${fixture}/precrash-target" "${residue}"
            ;;
        absent:mid_cleanup)
            [[ ! -e "${target}" && -d "${residue}" ]]
            ! diff -r --no-dereference "${fixture}/precrash-target" "${residue}" >/dev/null
            find "${residue}" -mindepth 1 -print -quit | grep -q .
            ;;
        *) printf 'invalid restore crash oracle: %s/%s\n' "${state}" "${point}" >&2; return 1 ;;
    esac
}

assert_restore_hook_marker() {
    local fixture="$1" state="$2" logical="$3" point="$4" residue="$5" operation_id="$6" metadata="$7"
    local marker="${fixture}/restore-hook-reached.json" nonce
    nonce="$(cut -f4 "${fixture}/restore-crash-control")"
    [[ "${nonce}" =~ ^[0-9a-f]{64}$ && -f "${marker}" && ! -L "${marker}" ]]
    [[ "$(stat -c '%a' "${marker}")" == 600 ]]
    /usr/bin/python3 -I - "${marker}" "${state}" "${logical}" "${point}" \
        "${residue}" "${operation_id}" "${nonce}" "${metadata}" <<'PY'
import json,sys
path,state,logical,point,residue,operation_id,nonce,metadata=sys.argv[1:]
with open(path,"r",encoding="utf-8") as handle:
    actual=json.load(handle)
expected={"version":1,"state":state,"logical":logical,"point":point,
          "residue":residue,"metadata":metadata,
          "operation_id":operation_id,"nonce":nonce}
if actual != expected: raise SystemExit("restore hook marker mismatch")
PY
    if find "${fixture}" -maxdepth 1 -name '.restore-hook-reached.tmp.*' -print -quit | grep -q .; then
        printf 'temporary restore hook marker residue remained\n' >&2
        return 1
    fi
}

index=0
if [[ "${section}" == all || "${section}" == success ]]; then
    printf 'test-only root restore-authority admission\n'
    assert_restore_authority_contract
    printf 'non-root sealed UI encrypted materialization\n'
    assert_nonroot_sealed_ui_materialize
    printf 'successful upgrade and explicit rollback rehearsal\n'
    fixture="${temp_root}/success-rollback"
    make_fixture "${fixture}" active
    rc="$(run_failure "${fixture}" success_rollback)"
    [[ "${rc}" == 0 ]] || {
        printf 'successful upgrade/rollback rehearsal returned %s\n' "${rc}" >&2
        cat "${fixture}/installer.log" >&2
        exit 1
    }
    grep -Fxq 'fixture_upgrade PASS' "${fixture}/rehearsal-results"
    grep -Fxq 'fixture_rollback PASS' "${fixture}/rehearsal-results"
    grep -Fxq 'fixture_fail_close PASS' "${fixture}/rehearsal-results"
    [[ "$(wc -l <"${fixture}/lifecycle-transcript.tsv")" == 9 ]]
    for completed_phase in after_accounts after_binaries after_ui_assets after_credentials \
        after_legacy_import after_units after_firewall after_services; do
        [[ "$(awk -F '\t' -v phase="${completed_phase}" \
            '$1==phase && $2=="production_function" && $3=="fixture_adapters" && $7==0 && $10=="nonroot_fixture" {count++} END {print count+0}' \
            "${fixture}/lifecycle-transcript.tsv")" == 1 ]] || {
            printf 'missing production phase transcript: %s\n' "${completed_phase}" >&2
            cat "${fixture}/lifecycle-transcript.tsv" >&2
            exit 1
        }
    done
    diff -r --no-dereference "${fixture}/expected-system" "${fixture}/system"
    diff -r --no-dereference "${fixture}/expected-runtime" "${fixture}/runtime"
    for restored_ui_directory in web web/static; do
        [[ "$(stat -c '%a' "${fixture}/system/usr/local/share/pgw/${restored_ui_directory}")" == \
           "$(stat -c '%a' "${fixture}/expected-system/usr/local/share/pgw/${restored_ui_directory}")" ]] \
            || { printf 'rollback did not restore UI directory mode: %s\n' "${restored_ui_directory}" >&2; exit 1; }
    done
    cmp -s "${fixture}/system/usr/local/share/pgw/web/static/app.js" \
        "${fixture}/expected-system/usr/local/share/pgw/web/static/app.js" \
        || { printf 'rollback did not restore UI asset content\n' >&2; exit 1; }
    [[ ! -e "${fixture}/system/var/lib/pgw-lifecycle/recovery.journal" ]]
    snapshot="$(find "${fixture}/backups" -mindepth 1 -maxdepth 1 -type d -name 'install.*' -print -quit)"
    [[ -n "${snapshot}" && -f "${snapshot}/snapshot.sha256" && -f "${snapshot}/snapshot.hmac" ]]
    if [[ -n "${evidence_dir}" ]]; then
        [[ "${evidence_dir}" == /* && -d "${evidence_dir}" && ! -L "${evidence_dir}" &&
           "$(stat -c '%u' "${evidence_dir}")" == "${EUID}" ]] || {
            printf 'invalid transaction evidence directory\n' >&2
            exit 1
        }
        install -m 0644 "${fixture}/lifecycle-transcript.tsv" \
            "${evidence_dir}/lifecycle-transcript.tsv"
        install -m 0644 "${fixture}/validation-transcript.tsv" \
            "${evidence_dir}/validation-transcript.tsv"
        install -m 0644 "${fixture}/rehearsal-results" \
            "${evidence_dir}/fixture-results.manifest"
    fi
fi

if [[ "${section}" == all || "${section}" == boundaries ]]; then
  for boundary in "${BOUNDARIES[@]}"; do
    printf 'transaction boundary: %s\n' "${boundary}"
    fixture="${temp_root}/${boundary}"
    mode=active; ((index++)) || true
    ((index % 2 == 0)) && mode=inactive
    make_fixture "${fixture}" "${mode}"
    rc="$(run_failure "${fixture}" "${boundary}")"
    [[ "${rc}" == 1 ]] || { printf 'unexpected rc %s at %s\n' "${rc}" "${boundary}" >&2; cat "${fixture}/installer.log" >&2; exit 1; }
    grep -Fq "injected failure at ${boundary}" "${fixture}/installer.log" || {
        cat "${fixture}/installer.log" >&2
        exit 1
    }
    diff -r --no-dereference "${fixture}/expected-system" "${fixture}/system"
    diff -r --no-dereference "${fixture}/expected-runtime" "${fixture}/runtime" || {
        cat "${fixture}/installer.log" >&2
        cat "${fixture}/commands.log" >&2
        exit 1
    }
    [[ ! -e "${fixture}/system/usr/local/sbin/pgw-verify-base" ]]
    grep -q $'^pgw-ui.service\tenabled-runtime\tactive' "${fixture}/runtime/services"
    grep -q $'^pgw-fwd@15002.service\tenabled-runtime\tinactive' "${fixture}/runtime/services"
    agent_stop_line="$(grep -nF 'systemctl --no-block stop pgw-agent.service' "${fixture}/commands.log" | head -n1 | cut -d: -f1)"
    forwarder_stop_line="$(grep -nF 'systemctl --no-block stop pgw-fwd@15001.service' "${fixture}/commands.log" | head -n1 | cut -d: -f1)"
    [[ -n "${agent_stop_line}" && -n "${forwarder_stop_line}" && "${agent_stop_line}" -lt "${forwarder_stop_line}" ]]
    if [[ "${boundary}" == after_services ]]; then
        grep -Fq 'https://pgw.fixture.test:8081/login' "${fixture}/ui-smoke.log"
        for asset in app.js styles.css login.js layout.css; do
            grep -Fq "https://pgw.fixture.test:8081/static/${asset}" "${fixture}/ui-smoke.log"
        done
    fi
    grep -Fxq "forwarding-closed-before:${boundary}" "${fixture}/wan-sentinel.log"
    ! grep -Fq 'forwarding-open-before:' "${fixture}/wan-sentinel.log"
done

  for fresh_ui_boundary in after_binaries after_ui_assets; do
      printf 'fresh-install absent UI rollback: %s\n' "${fresh_ui_boundary}"
      fixture="${temp_root}/fresh-ui-${fresh_ui_boundary}"
      make_fixture "${fixture}" active
      rm -rf -- "${fixture}/system/usr/local/share/pgw/web" \
          "${fixture}/expected-system/usr/local/share/pgw/web"
      rc="$(run_failure "${fixture}" "${fresh_ui_boundary}")"
      [[ "${rc}" == 1 ]] || {
          printf 'fresh absent UI rollback %s returned %s, wanted 1\n' \
              "${fresh_ui_boundary}" "${rc}" >&2
          cat "${fixture}/installer.log" >&2
          exit 1
      }
      [[ ! -e "${fixture}/system/usr/local/share/pgw/web" &&
         ! -L "${fixture}/system/usr/local/share/pgw/web" ]] \
          || { printf 'fresh absent UI rollback published residue: %s\n' "${fresh_ui_boundary}" >&2; exit 1; }
      if find "${fixture}/system/usr/local/share/pgw" "${fixture}/system/run/pgw" \
          -maxdepth 1 \( -name '.web.new.*' -o -name '.pgw-restore-*' -o \
          -name 'snapshot-restore.install.*' \) -print -quit | grep -q .; then
          printf 'fresh absent UI rollback left restore residue: %s\n' "${fresh_ui_boundary}" >&2
          exit 1
      fi
      diff -r --no-dereference "${fixture}/expected-system" "${fixture}/system"
      diff -r --no-dereference "${fixture}/expected-runtime" "${fixture}/runtime"
  done

  for fresh_ui_target in file symlink; do
      printf 'fresh-install absent UI non-directory rollback: %s\n' "${fresh_ui_target}"
      fixture="${temp_root}/fresh-ui-target-${fresh_ui_target}"
      make_fixture "${fixture}" active
      rm -rf -- "${fixture}/system/usr/local/share/pgw/web" \
          "${fixture}/expected-system/usr/local/share/pgw/web"
      rc="$(run_failure "${fixture}" "absent_ui_target:${fresh_ui_target}")"
      [[ "${rc}" == 1 ]] || {
          printf 'fresh absent UI %s target rollback returned %s, wanted 1\n' \
              "${fresh_ui_target}" "${rc}" >&2
          cat "${fixture}/installer.log" >&2
          exit 1
      }
      grep -Fq "restore_snapshot.py absent /dev/null ${fixture}/system/usr/local/share/pgw/web" \
          "${fixture}/commands.log" \
          || { printf 'absent UI %s target did not reach production restore helper\n' "${fresh_ui_target}" >&2; exit 1; }
      [[ ! -e "${fixture}/system/usr/local/share/pgw/web" &&
         ! -L "${fixture}/system/usr/local/share/pgw/web" ]] \
          || { printf 'absent UI %s target survived rollback\n' "${fresh_ui_target}" >&2; exit 1; }
      if [[ "${fresh_ui_target}" == symlink ]]; then
          grep -Fxq 'outside UI sentinel' "${fixture}/outside-ui-sentinel" \
              || { printf 'absent UI symlink rollback changed external target\n' >&2; exit 1; }
      fi
      diff -r --no-dereference "${fixture}/expected-system" "${fixture}/system"
      diff -r --no-dereference "${fixture}/expected-runtime" "${fixture}/runtime"
  done

  printf 'capture resource boundary: depth/state-only recovery\n'
  fixture="${temp_root}/capture-resource-depth"
  make_fixture "${fixture}" active
  deep_path="${fixture}/system/var/lib/pgw"
  for depth_index in $(seq 1 35); do
      deep_path="${deep_path}/d${depth_index}"
      install -d "${deep_path}"
  done
  printf 'bounded-capture\n' >"${deep_path}/state"
  rm -rf -- "${fixture}/expected-system"
  cp -a -- "${fixture}/system" "${fixture}/expected-system"
  rc="$(run_failure "${fixture}" after_services)"
  [[ "${rc}" == 1 ]] || {
      printf 'capture resource failure returned %s, wanted 1\n' "${rc}" >&2
      cat "${fixture}/installer.log" >&2
      exit 1
  }
  grep -Fq 'resource_limit: max_depth' "${fixture}/installer.log"
  grep -Fq 'recovering pre-ready capture from service/runtime state only' "${fixture}/installer.log"
  ! grep -Fq 'automatic rollback was partial or failed' "${fixture}/installer.log"
  diff -r --no-dereference "${fixture}/expected-system" "${fixture}/system"
  diff -r --no-dereference "${fixture}/expected-runtime" "${fixture}/runtime"
  capture_snapshot="$(find "${fixture}/backups" -mindepth 1 -maxdepth 1 -type d -name 'install.*' -print -quit)"
  [[ -n "${capture_snapshot}" && ! -e "${capture_snapshot}/snapshot.sha256" && \
     ! -e "${capture_snapshot}/snapshot.hmac" ]]
  [[ ! -e "${fixture}/system/var/lib/pgw-lifecycle/recovery.journal" ]]
  ! grep -Eq 'python3 .*restore_snapshot.py verify ' "${fixture}/commands.log"

  if [[ "$(uname -s)" == Linux ]]; then
      printf 'capture resource boundary: nofile/state-only recovery\n'
      fixture="${temp_root}/capture-resource-nofile"
      make_fixture "${fixture}" active
      rc="$(run_failure_low_fd "${fixture}" after_services)"
      [[ "${rc}" == 1 ]] || {
          printf 'capture nofile failure returned %s, wanted 1\n' "${rc}" >&2
          cat "${fixture}/installer.log" >&2
          exit 1
      }
      grep -Fq 'resource_limit: nofile' "${fixture}/installer.log"
      grep -Fq 'recovering pre-ready capture from service/runtime state only' "${fixture}/installer.log"
      ! grep -Fq 'automatic rollback was partial or failed' "${fixture}/installer.log"
      diff -r --no-dereference "${fixture}/expected-system" "${fixture}/system"
      diff -r --no-dereference "${fixture}/expected-runtime" "${fixture}/runtime"
      capture_snapshot="$(find "${fixture}/backups" -mindepth 1 -maxdepth 1 -type d -name 'install.*' -print -quit)"
      [[ -n "${capture_snapshot}" && ! -e "${capture_snapshot}/snapshot.sha256" && \
         ! -e "${capture_snapshot}/snapshot.hmac" ]]
      [[ ! -e "${fixture}/system/var/lib/pgw-lifecycle/recovery.journal" ]]
      [[ "$(grep -Ec 'python3 .*restore_snapshot.py verify ' "${fixture}/commands.log")" == 1 ]]
  else
      printf 'capture resource nofile lifecycle: SKIP non-Linux\n'
  fi
fi

if [[ "${section}" == all || "${section}" == capture-crash ]]; then
  for capture_point in journal quiesced payload sealed; do
      printf 'capture lifecycle crash: %s\n' "${capture_point}"
      fixture="${temp_root}/capture-crash-${capture_point}"
      make_fixture "${fixture}" active
      rc="$(run_failure "${fixture}" "crash_capture:${capture_point}")"
      [[ "${rc}" == 137 ]] || {
          printf 'capture crash %s returned %s, wanted SIGKILL rc 137\n' "${capture_point}" "${rc}" >&2
          cat "${fixture}/installer.log" >&2
          exit 1
      }
      journal="${fixture}/system/var/lib/pgw-lifecycle/recovery.journal"
      [[ -f "${journal}" && ! -L "${journal}" ]]
      [[ "$(uname -s)" != Linux || "$(stat -c '%a' "${journal}")" == 600 ]]
      grep -Fxq 'phase=capturing' "${journal}"
      grep -Eq '^state_hash=[0-9a-f]{64}$' "${journal}"
      grep -Eq '^auth=[0-9a-f]{64}$' "${journal}"
      snapshot="$(sed -n 's/^snapshot=//p' "${journal}")"
      fixture_real="$(cd -- "${fixture}" && pwd -P)"
      [[ "${snapshot}" == "${fixture_real}/backups"/install.* ]]
      case "${capture_point}" in
          journal)
              diff -r --no-dereference "${fixture}/expected-runtime" "${fixture}/runtime"
              [[ ! -e "${snapshot}/snapshot.sha256" && ! -e "${snapshot}/snapshot.hmac" ]]
              ;;
          quiesced)
              [[ "$(tr -d '[:space:]' <"${fixture}/runtime/ip-forward")" == 0 ]]
              ! awk -F '\t' '$3=="active" {found=1} END {exit found?0:1}' "${fixture}/runtime/services"
              [[ ! -d "${snapshot}/objects" || -z "$(find "${snapshot}/objects" -mindepth 1 -print -quit)" ]]
              ;;
          payload)
              [[ "$(tr -d '[:space:]' <"${fixture}/runtime/ip-forward")" == 0 ]]
              find "${snapshot}/objects" -mindepth 1 -print -quit | grep -q .
              [[ ! -e "${snapshot}/snapshot.sha256" && ! -e "${snapshot}/snapshot.hmac" ]]
              ;;
          sealed)
              [[ "$(tr -d '[:space:]' <"${fixture}/runtime/ip-forward")" == 0 ]]
              [[ -f "${snapshot}/snapshot.sha256" && -f "${snapshot}/snapshot.hmac" ]]
              ;;
      esac
      recover_rc="$(run_failure "${fixture}" recover)"
      [[ "${recover_rc}" == 0 ]] || {
          printf 'capture crash recovery %s returned %s\n' "${capture_point}" "${recover_rc}" >&2
          cat "${fixture}/installer.log" >&2
          exit 1
      }
      diff -r --no-dereference "${fixture}/expected-system" "${fixture}/system"
      diff -r --no-dereference "${fixture}/expected-runtime" "${fixture}/runtime"
      [[ ! -e "${journal}" ]]
      if [[ "${capture_point}" == sealed ]]; then
          grep -Fq 'recovered sealed capture before ready publication' "${fixture}/installer.log"
          ! grep -Fq 'state evidence only' "${fixture}/installer.log"
      else
          grep -Fq 'state evidence only' "${fixture}/installer.log"
      fi
  done
fi

if [[ "${section}" == all || "${section}" == restore ]]; then
  for restore_failure in "${RESTORE_FAILURES[@]}"; do
    printf 'restore failure boundary: %s\n' "${restore_failure}"
    fixture="${temp_root}/restore-${restore_failure}"
    make_fixture "${fixture}" active
    rc="$(run_failure "${fixture}" after_services "${restore_failure}")"
    [[ "${rc}" == 125 ]] || { printf 'rollback failure %s returned %s, wanted 125\n' "${restore_failure}" "${rc}" >&2; exit 1; }
    grep -Fq 'CRITICAL: automatic rollback was partial or failed' "${fixture}/installer.log"
    if [[ "${restore_failure}" == quiesce || "${restore_failure}" == copy ]]; then
        [[ "$(stat -c '%a' "${fixture}/system/usr/local/share/pgw/web")" == 550 &&
           "$(stat -c '%a' "${fixture}/system/usr/local/share/pgw/web/static")" == 550 ]] \
            || { printf 'pre-copy restore failure changed sealed UI modes: %s\n' "${restore_failure}" >&2; exit 1; }
        # Cleanup is outside the failure-boundary assertion and needs the same
        # test-only authority that production root has over the sealed tree.
        PGW_FAKE_ROOT="${fixture}" "${fixture}/fake-bin/lifecycle" restore-authority \
            "${fixture}/system/usr/local/share/pgw/web"
    fi
  done
fi

if [[ "${section}" == all || "${section}" == restore-crash ]]; then
  if [[ "$(uname -s)" != Linux ]]; then
    [[ "${PGW_REQUIRE_LINUX_RESTORE_CRASH:-0}" != 1 ]] || {
        printf 'Linux restoring-journal SIGKILL evidence was required but unavailable\n' >&2
        exit 1
    }
    printf 'installer restoring-journal SIGKILL tests: SKIP non-Linux\n'
  else
    for crash_state in present absent; do
      for crash_point in partial_stage post_exchange mid_cleanup; do
        printf 'restore lifecycle crash: %s/%s\n' "${crash_state}" "${crash_point}"
        crash_fixture="${temp_root}/restore-crash-${crash_state}-${crash_point}"
        make_fixture "${crash_fixture}" active
        cp "${ROOT}/deploy/tests/restore_crash_driver.py" "${crash_fixture}/restore-crash-driver.py"
        chmod 0700 "${crash_fixture}/restore-crash-driver.py"
        crash_rc="$(run_failure "${crash_fixture}" "restore_crash:${crash_state}:${crash_point}")"
        [[ "${crash_rc}" == 137 ]] || {
            printf 'restore crash %s/%s returned %s, wanted SIGKILL rc 137\n' \
                "${crash_state}" "${crash_point}" "${crash_rc}" >&2
            cat "${crash_fixture}/installer.log" >&2
            exit 1
        }
        journal="${crash_fixture}/system/var/lib/pgw-lifecycle/recovery.journal"
        [[ -f "${journal}" && "$(stat -c '%a' "${journal}")" == 600 ]]
        grep -Fxq 'version=1' "${journal}"
        grep -Fxq 'phase=restoring' "${journal}"
        grep -Fxq 'restore_phase=prepared' "${journal}"
        if [[ "${crash_state}" == present ]]; then
            logical=/var/lib/pgw
        else
            logical=/etc/pgw/credential-inbox
        fi
        grep -Fxq "restore_state=${crash_state}" "${journal}"
        grep -Fxq "restore_path=${logical}" "${journal}"
        snapshot="$(sed -n 's/^snapshot=//p' "${journal}")"
        journal_id="$(sed -n 's/^operation_id=//p' "${journal}")"
        expected_id="$({ cat "${snapshot}/payload.manifest.json"; printf '\0%s\0%s' "${logical}" "${crash_state}"; } \
            | sha256sum | awk '{print $1}')"
        [[ "${journal_id}" == "${expected_id}" && "${journal_id}" =~ ^[0-9a-f]{64}$ ]]
        [[ "$(tr -d '[:space:]' <"${crash_fixture}/runtime/ip-forward")" == 0 ]]
        restore_stage="${crash_fixture}/system/run/pgw/snapshot-restore.$(basename -- "${snapshot}")"
        residue_digest="$({ cat "${restore_stage}/metadata.json"; printf '\0%s' "${logical}"; } \
            | sha256sum | awk '{print $1}')"
        [[ "${crash_state}" == present ]] && residue_kind=stage || residue_kind=tomb
        residue_name=".pgw-restore-${residue_kind}-${residue_digest:0:24}"
        assert_restore_hook_marker "${crash_fixture}" "${crash_state}" "${logical}" \
            "${crash_point}" "${residue_name}" "${expected_id}" \
            "${restore_stage}/metadata.json"
        assert_restore_crash_phase "${crash_fixture}" "${snapshot}" \
            "${crash_state}" "${crash_point}" "${logical}"
        recover_rc="$(run_failure "${crash_fixture}" recover_restore_crash)"
        [[ "${recover_rc}" == 0 ]] || {
            printf 'restore crash recovery %s/%s returned %s\n' \
                "${crash_state}" "${crash_point}" "${recover_rc}" >&2
            cat "${crash_fixture}/installer.log" >&2
            exit 1
        }
        grep -Fq 'recovered interrupted deterministic restore operation' \
            "${crash_fixture}/installer.log"
        [[ ! -e "${journal}" ]]
        [[ -f "${snapshot}/payload.manifest.json" && -d "${snapshot}/objects" ]]
        if find "${crash_fixture}/system" \
            \( -name '.pgw-restore-*' -o -name '.recovery.*' \) -print -quit | grep -q .; then
            printf 'restore residue remained after %s/%s recovery\n' \
                "${crash_state}" "${crash_point}" >&2
            exit 1
        fi
        diff -r --no-dereference "${crash_fixture}/expected-system" "${crash_fixture}/system"
        diff -r --no-dereference "${crash_fixture}/expected-runtime" "${crash_fixture}/runtime"
        grep -Fq 'journal-present-at-forwarding-final' "${crash_fixture}/commands.log"
        [[ ! -e "${crash_fixture}/restore-crash-control" ]]
        rm -f -- "${crash_fixture}/restore-hook-reached.json"
        [[ ! -e "${crash_fixture}/restore-hook-reached.json" ]]
      done
    done
    printf 'installer restoring-journal SIGKILL tests: PASS\n'
  fi
fi

if [[ "${section}" == all || "${section}" == crash ]]; then
    for legacy_crash in crash_legacy_sealed crash_legacy_post_import; do
    printf 'legacy sealed-stage SIGKILL recovery boundary\n'
    crash_fixture="${temp_root}/legacy-sealed-${legacy_crash}"
    make_fixture "${crash_fixture}" active
    printf '{"legacy":"fixture"}\n' >"${crash_fixture}/system/var/lib/pgw/state.json"
    cp -- "${crash_fixture}/system/var/lib/pgw/state.json" "${crash_fixture}/expected-system/var/lib/pgw/state.json"
    crash_rc="$(run_failure "${crash_fixture}" "${legacy_crash}")"
    [[ "${crash_rc}" == 137 ]] || { printf 'legacy sealed crash returned %s, wanted 137\n' "${crash_rc}" >&2; exit 1; }
    journal="${crash_fixture}/system/var/lib/pgw-lifecycle/recovery.journal"
    snapshot="$(sed -n 's/^snapshot=//p' "${journal}")"
    [[ -f "${journal}" && "${snapshot}" == "${crash_fixture}/backups"/install.* ]]
    sealed_stage="${crash_fixture}/system/run/pgw/legacy-sealed.$(basename -- "${snapshot}")"
    [[ -d "${sealed_stage}" && ! -L "${sealed_stage}" ]]
    if [[ "${legacy_crash}" == crash_legacy_post_import ]]; then
        [[ -f "${crash_fixture}/system/run/pgw/legacy-import/report.json" ]]
    fi
    # A sibling is a no-delete canary: recovery may remove only the identity-
    # derived stage, never glob or recursively clean /run/pgw.
    mkdir -p "${crash_fixture}/system/run/pgw/legacy-sealed.not-snapshot"
    mkdir -p "${crash_fixture}/expected-system/run/pgw/legacy-sealed.not-snapshot"
    recover_rc="$(run_failure "${crash_fixture}" recover)"
    [[ "${recover_rc}" == 0 ]] || { printf 'legacy sealed recovery returned %s\n' "${recover_rc}" >&2; cat "${crash_fixture}/installer.log" >&2; exit 1; }
    [[ ! -e "${sealed_stage}" && -d "${crash_fixture}/system/run/pgw/legacy-sealed.not-snapshot" ]]
    [[ ! -e "${crash_fixture}/system/run/pgw/legacy-import" ]]
    if find "${crash_fixture}/system/run/pgw" -name 'legacy-sealed.install.*' -print -quit | grep -q .; then
        printf 'plaintext legacy sealed stage remained after authenticated recovery\n' >&2
        exit 1
    fi
    diff -r --no-dereference "${crash_fixture}/expected-system" "${crash_fixture}/system"
    diff -r --no-dereference "${crash_fixture}/expected-runtime" "${crash_fixture}/runtime"
    done

    # Exact-stage residue is fail-closed across repeated startups. Repairing
    # only the exact target permits recovery; unrelated siblings survive.
    for residue_kind in malformed symlink; do
        crash_fixture="${temp_root}/legacy-sealed-${residue_kind}"
        make_fixture "${crash_fixture}" active
        printf '{"legacy":"fixture"}\n' >"${crash_fixture}/system/var/lib/pgw/state.json"
        cp -- "${crash_fixture}/system/var/lib/pgw/state.json" "${crash_fixture}/expected-system/var/lib/pgw/state.json"
        crash_rc="$(run_failure "${crash_fixture}" crash_legacy_sealed)"
        [[ "${crash_rc}" == 137 ]]
        journal="${crash_fixture}/system/var/lib/pgw-lifecycle/recovery.journal"
        snapshot="$(sed -n 's/^snapshot=//p' "${journal}")"
        sealed_stage="${crash_fixture}/system/run/pgw/legacy-sealed.$(basename -- "${snapshot}")"
        stage_sibling="${crash_fixture}/system/run/pgw/legacy-sealed.not-snapshot"
        saved_stage="${crash_fixture}/system/run/pgw/legacy-stage-saved-${residue_kind}"
        mkdir -p "${stage_sibling}"
        case "${residue_kind}" in
            malformed) chmod 0750 "${sealed_stage}" ;;
            symlink)
                mv -- "${sealed_stage}" "${saved_stage}"
                ln -s "$(basename -- "${saved_stage}")" "${sealed_stage}"
                ;;
        esac
        for recovery_attempt in 1 2; do
            recover_rc="$(run_failure "${crash_fixture}" recover)"
            [[ "${recover_rc}" != 0 && -f "${journal}" ]]
            grep -Eq '^auth=[0-9a-f]{64}$' "${journal}"
            [[ -d "${stage_sibling}" ]]
            [[ "$(tr -d '[:space:]' <"${crash_fixture}/runtime/ip-forward")" == 0 ]]
        done
        case "${residue_kind}" in
            malformed) chmod 0700 "${sealed_stage}" ;;
            symlink)
                rm -f -- "${sealed_stage}"
                mv -- "${saved_stage}" "${sealed_stage}"
                ;;
        esac
        recover_rc="$(run_failure "${crash_fixture}" recover)"
        [[ "${recover_rc}" == 0 && ! -e "${journal}" && ! -e "${sealed_stage}" && -d "${stage_sibling}" ]]
        rm -rf -- "${stage_sibling}"
        diff -r --no-dereference "${crash_fixture}/expected-system" "${crash_fixture}/system"
    done

    # The fixed legacy-import/report.json residue has the same durable retry
    # contract. Exercise hostile directory and report types/modes without ever
    # broad-deleting the sibling canary.
    for residue_kind in runtime-mode runtime-symlink report-mode report-symlink; do
        crash_fixture="${temp_root}/legacy-report-${residue_kind}"
        make_fixture "${crash_fixture}" active
        printf '{"legacy":"fixture"}\n' >"${crash_fixture}/system/var/lib/pgw/state.json"
        cp -- "${crash_fixture}/system/var/lib/pgw/state.json" "${crash_fixture}/expected-system/var/lib/pgw/state.json"
        crash_rc="$(run_failure "${crash_fixture}" crash_legacy_post_import)"
        [[ "${crash_rc}" == 137 ]]
        journal="${crash_fixture}/system/var/lib/pgw-lifecycle/recovery.journal"
        snapshot="$(sed -n 's/^snapshot=//p' "${journal}")"
        sealed_stage="${crash_fixture}/system/run/pgw/legacy-sealed.$(basename -- "${snapshot}")"
        report_runtime="${crash_fixture}/system/run/pgw/legacy-import"
        report_file="${report_runtime}/report.json"
        report_sibling="${crash_fixture}/system/run/pgw/legacy-report-sibling"
        saved_runtime="${crash_fixture}/system/run/pgw/legacy-import-saved"
        saved_report="${crash_fixture}/system/run/pgw/legacy-report-saved.json"
        mkdir -p "${report_sibling}"
        case "${residue_kind}" in
            runtime-mode) chmod 0750 "${report_runtime}" ;;
            runtime-symlink)
                mv -- "${report_runtime}" "${saved_runtime}"
                ln -s "$(basename -- "${saved_runtime}")" "${report_runtime}"
                ;;
            report-mode) chmod 0640 "${report_file}" ;;
            report-symlink)
                mv -- "${report_file}" "${saved_report}"
                ln -s "../$(basename -- "${saved_report}")" "${report_file}"
                ;;
        esac
        for recovery_attempt in 1 2; do
            recover_rc="$(run_failure "${crash_fixture}" recover)"
            [[ "${recover_rc}" != 0 && -f "${journal}" && -e "${sealed_stage}" ]]
            grep -Eq '^auth=[0-9a-f]{64}$' "${journal}"
            [[ -d "${report_sibling}" ]]
            [[ "$(tr -d '[:space:]' <"${crash_fixture}/runtime/ip-forward")" == 0 ]]
        done
        case "${residue_kind}" in
            runtime-mode) chmod 0700 "${report_runtime}" ;;
            runtime-symlink)
                rm -f -- "${report_runtime}"
                mv -- "${saved_runtime}" "${report_runtime}"
                ;;
            report-mode) chmod 0600 "${report_file}" ;;
            report-symlink)
                rm -f -- "${report_file}"
                mv -- "${saved_report}" "${report_file}"
                ;;
        esac
        recover_rc="$(run_failure "${crash_fixture}" recover)"
        [[ "${recover_rc}" == 0 && ! -e "${journal}" && ! -e "${sealed_stage}" && ! -e "${report_runtime}" && -d "${report_sibling}" ]]
        rm -rf -- "${report_sibling}"
        diff -r --no-dereference "${crash_fixture}/expected-system" "${crash_fixture}/system"
    done

    crash_fixture="${temp_root}/crash-ready"
    printf 'crash recovery boundary: ready snapshot\n'
    make_fixture "${crash_fixture}" active
    crash_rc="$(run_failure "${crash_fixture}" crash_ready)"
    [[ "${crash_rc}" == 99 ]] || { printf 'crash-ready returned %s, wanted 99\n' "${crash_rc}" >&2; cat "${crash_fixture}/installer.log" >&2; exit 1; }
    [[ -f "${crash_fixture}/system/var/lib/pgw-lifecycle/recovery.journal" ]] || { printf 'crash-ready did not retain recovery journal\n' >&2; exit 1; }
    journal_mode_owner="$(stat -c '%a:%u' "${crash_fixture}/system/var/lib/pgw-lifecycle/recovery.journal")"
    recover_rc="$(run_failure "${crash_fixture}" recover)"
    [[ "${recover_rc}" == 0 ]] || { printf 'startup recovery returned %s, wanted 0 (journal %s, euid %s)\n' "${recover_rc}" "${journal_mode_owner}" "${EUID}" >&2; cat "${crash_fixture}/installer.log" >&2; exit 1; }
    [[ ! -e "${crash_fixture}/system/var/lib/pgw-lifecycle/recovery.journal" ]] || { printf 'startup recovery did not clear journal\n' >&2; exit 1; }
    diff -r --no-dereference "${crash_fixture}/expected-system" "${crash_fixture}/system"
    diff -r --no-dereference "${crash_fixture}/expected-runtime" "${crash_fixture}/runtime"

    for recovery_phase in ready restoring; do
        printf 'full snapshot recovery failure remains fail-closed: %s\n' "${recovery_phase}"
        crash_fixture="${temp_root}/full-recovery-failure-${recovery_phase}"
        make_fixture "${crash_fixture}" active
        if [[ "${recovery_phase}" == ready ]]; then
            seed_rc="$(run_failure "${crash_fixture}" crash_ready)"
            [[ "${seed_rc}" == 99 ]]
        else
            seed_rc="$(run_failure "${crash_fixture}" after_services runtime_apply)"
            [[ "${seed_rc}" == 125 ]]
        fi
        journal="${crash_fixture}/system/var/lib/pgw-lifecycle/recovery.journal"
        grep -Fxq "phase=${recovery_phase}" "${journal}"
        grep -Eq '^auth=[0-9a-f]{64}$' "${journal}"
        recover_rc="$(run_failure "${crash_fixture}" recover runtime_apply)"
        [[ "${recover_rc}" == 125 ]] || {
            printf '%s full recovery failure returned %s, wanted 125\n' \
                "${recovery_phase}" "${recover_rc}" >&2
            cat "${crash_fixture}/installer.log" >&2
            exit 1
        }
        grep -Fq 'CRITICAL: automatic rollback was partial or failed' "${crash_fixture}/installer.log"
        ! grep -Fq 'state evidence only' "${crash_fixture}/installer.log"
        [[ "$(tr -d '[:space:]' <"${crash_fixture}/runtime/ip-forward")" == 0 ]]
        ! awk -F '\t' '$1 ~ /^pgw-/ && $3=="active" {found=1} END {exit found?0:1}' \
            "${crash_fixture}/runtime/services"
        [[ -f "${journal}" ]]
        grep -Fxq 'phase=restoring' "${journal}"
        grep -Eq '^auth=[0-9a-f]{64}$' "${journal}"
    done
fi

if [[ "${section}" == all || "${section}" == tamper ]]; then
    tamper_fixture="${temp_root}/tampered-snapshot"
    printf 'snapshot authentication boundary: tampered payload\n'
    make_fixture "${tamper_fixture}" active
    tamper_rc="$(run_failure "${tamper_fixture}" tamper_snapshot)"
    [[ "${tamper_rc}" == 125 ]] || { printf 'tampered snapshot returned %s, wanted 125\n' "${tamper_rc}" >&2; cat "${tamper_fixture}/installer.log" >&2; exit 1; }
    grep -Fq 'snapshot authentication failed' "${tamper_fixture}/installer.log"
    grep -Fq 'CRITICAL: automatic rollback was partial or failed' "${tamper_fixture}/installer.log"

    printf 'recovery journal authentication boundary: phase tamper\n'
    journal_fixture="${temp_root}/tampered-recovery-journal"
    make_fixture "${journal_fixture}" active
    seed_rc="$(run_failure "${journal_fixture}" crash_ready)"
    [[ "${seed_rc}" == 99 ]]
    journal="${journal_fixture}/system/var/lib/pgw-lifecycle/recovery.journal"
    sed -i 's/^phase=ready$/phase=capturing/' "${journal}"
    tamper_rc="$(run_failure "${journal_fixture}" recover)"
    [[ "${tamper_rc}" == 125 ]]
    grep -Fq 'unauthenticated lifecycle recovery journal' "${journal_fixture}/installer.log"
    ! grep -Fq 'state evidence only' "${journal_fixture}/installer.log"
    [[ "$(tr -d '[:space:]' <"${journal_fixture}/runtime/ip-forward")" == 0 ]]
    ! awk -F '\t' '$1 ~ /^pgw-/ && $3=="active" {found=1} END {exit found?0:1}' \
        "${journal_fixture}/runtime/services"
    [[ -f "${journal}" ]]
fi

printf 'installer production transaction failure-boundary tests: PASS\n'
