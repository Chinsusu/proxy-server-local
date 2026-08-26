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
cleanup_writable_dirs=()
make_registered_cleanup_dirs_writable() {
    if ((${#cleanup_writable_dirs[@]})); then
        /usr/bin/python3 -I - "${temp_root}" "${cleanup_writable_dirs[@]}" <<'PY'
import os
import stat
import sys

root, *targets = sys.argv[1:]
allowed = {
    "capture-resource-depth/system/usr/local/share/pgw/web",
    "capture-resource-depth/system/usr/local/share/pgw/web/static",
    "capture-resource-depth/expected-system/usr/local/share/pgw/web",
    "capture-resource-depth/expected-system/usr/local/share/pgw/web/static",
}
if (not os.path.isabs(root) or os.path.normpath(root) != root
        or len(targets) != 4):
    raise SystemExit("unsafe registered cleanup root")
relative_targets = []
for target in targets:
    if not os.path.isabs(target) or os.path.normpath(target) != target:
        raise SystemExit("unsafe registered cleanup path")
    relative = os.path.relpath(target, root)
    if relative not in allowed:
        raise SystemExit("unregistered cleanup path")
    relative_targets.append(relative)
if set(relative_targets) != allowed:
    raise SystemExit("incomplete registered cleanup paths")

flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
descriptor = os.open(os.sep, flags)
try:
    for component in (part for part in root.split(os.sep) if part):
        child = os.open(component, flags, dir_fd=descriptor)
        info = os.fstat(child)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid())
                or info.st_mode & 0o022):
            os.close(child)
            raise SystemExit("unsafe registered cleanup ancestor")
        os.close(descriptor)
        descriptor = child
    root_fd = descriptor
    descriptor = -1
    for relative in relative_targets:
        current = os.dup(root_fd)
        try:
            missing = False
            for component in relative.split("/"):
                try:
                    child = os.open(component, flags, dir_fd=current)
                except FileNotFoundError:
                    missing = True
                    break
                info = os.fstat(child)
                if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                        or info.st_mode & 0o022):
                    os.close(child)
                    raise SystemExit("unsafe registered cleanup directory")
                os.close(current)
                current = child
            if not missing:
                info = os.fstat(current)
                os.fchmod(current, stat.S_IMODE(info.st_mode) | 0o700)
        finally:
            os.close(current)
    os.close(root_fd)
finally:
    if descriptor >= 0:
        os.close(descriptor)
PY
    fi
}
cleanup() {
    local rc=$?
    trap - EXIT
    set +e
    make_registered_cleanup_dirs_writable
    rm -rf -- "${temp_root}"
    exit "${rc}"
}
trap cleanup EXIT

# The production release builder creates these artifacts after source
# admission. Build the same binaries below the already-private transaction
# root, never below the repository release tree consumed by production.
install -d -m 0700 "${artifact_root}"
for command_name in api agent fwd ui health snapshot-crypt; do
    artifact="${artifact_root}/pgw-${command_name}"
    # -modcacherw: callers with a private, single-use HOME (e.g.
    # rehearse-release.sh's sandboxed rehearsal) get a GOMODCACHE under that
    # HOME; Go's default read-only module cache files then make the
    # caller's own cleanup rm -rf fail. Same fix as build-release.sh's
    # run_go(), for the same reason.
    (cd -- "${ROOT}" && CGO_ENABLED=0 GOFLAGS=-modcacherw go build -trimpath -buildvcs=false -o "${artifact}" "./cmd/${command_name}")
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
    printf 'PGW_ADMIN_USER=fixture-admin\n' >"${system}/etc/pgw/pgw.env"
    chmod 0600 "${system}/etc/pgw/ui.crt" "${system}/etc/pgw/ui.key" \
        "${system}/etc/pgw/ui_proxy_token" "${system}/etc/pgw/admin_pass_hash"
    chmod 0640 "${system}/etc/pgw/pgw.env"
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

reset_fake_sysctl_contract_state() {
    local fixture="$1" command="$2"
    PGW_FAKE_ROOT="${fixture}" "${command}" stop systemd-sysctl.service
    printf '0\n' >"${fixture}/runtime/ip-forward"
    [[ "$(awk -F '\t' '$1=="systemd-sysctl.service" {print $3}' "${fixture}/runtime/services")" == inactive &&
       "$(tr -d '[:space:]' <"${fixture}/runtime/ip-forward")" == 0 ]]
}

assert_fake_sysctl_rejected() {
    local fixture="$1" command="$2" label="$3" external_digest="$4" timeout_seconds="${5:-}" rc current_digest
    reset_fake_sysctl_contract_state "${fixture}" "${command}"
    set +e
    if [[ -n "${timeout_seconds}" ]]; then
        PGW_FAKE_ROOT="${fixture}" /usr/bin/timeout --signal=TERM --kill-after=1s \
            "${timeout_seconds}s" "${command}" restart systemd-sysctl.service >/dev/null 2>&1
    else
        PGW_FAKE_ROOT="${fixture}" "${command}" restart systemd-sysctl.service >/dev/null 2>&1
    fi
    rc=$?
    set -e
    [[ "${rc}" == 2 ]] \
        || { printf '%s PGW sysctl rejection returned rc=%s, expected rc=2\n' "${label}" "${rc}" >&2; exit 1; }
    [[ "$(awk -F '\t' '$1=="systemd-sysctl.service" {print $3}' "${fixture}/runtime/services")" == inactive &&
       "$(tr -d '[:space:]' <"${fixture}/runtime/ip-forward")" == 0 ]] \
        || { printf '%s PGW sysctl rejection changed runtime state\n' "${label}" >&2; exit 1; }
    current_digest="$(/usr/bin/sha256sum -- "${fixture}/outside-sysctl" | awk '{print $1}')"
    [[ "${current_digest}" == "${external_digest}" ]] \
        || { printf '%s PGW sysctl rejection changed external config\n' "${label}" >&2; exit 1; }
}

assert_fake_sysctl_contract() {
    local fixture="${temp_root}/fake-sysctl-contract" command config external external_digest
    make_fixture "${fixture}" inactive
    command="${fixture}/fake-bin/systemctl"
    config="${fixture}/system/etc/sysctl.d/99-pgw.conf"
    external="${fixture}/outside-sysctl"
    printf 'net.ipv4.ip_forward = 1\n# external sysctl sentinel\n' >"${external}"
    external_digest="$(/usr/bin/sha256sum -- "${external}" | awk '{print $1}')"
    [[ "${external_digest}" =~ ^[0-9a-f]{64}$ ]] \
        || { printf 'could not capture external sysctl digest\n' >&2; exit 1; }

    reset_fake_sysctl_contract_state "${fixture}" "${command}"
    [[ ! -e "${config}" && ! -L "${config}" ]]
    PGW_FAKE_ROOT="${fixture}" "${command}" start systemd-sysctl.service
    [[ "$(awk -F '\t' '$1=="systemd-sysctl.service" {print $3}' "${fixture}/runtime/services")" == active &&
       "$(tr -d '[:space:]' <"${fixture}/runtime/ip-forward")" == 0 ]] \
        || { printf 'absent PGW sysctl config changed forwarding\n' >&2; exit 1; }

    reset_fake_sysctl_contract_state "${fixture}" "${command}"
    printf 'net.ipv4.ip_forward = 1\n' >"${config}"
    chmod 0644 "${config}"
    PGW_FAKE_ROOT="${fixture}" "${command}" restart systemd-sysctl.service
    [[ "$(awk -F '\t' '$1=="systemd-sysctl.service" {print $3}' "${fixture}/runtime/services")" == active &&
       "$(tr -d '[:space:]' <"${fixture}/runtime/ip-forward")" == 1 ]] \
        || { printf 'present PGW sysctl config was not applied\n' >&2; exit 1; }

    reset_fake_sysctl_contract_state "${fixture}" "${command}"
    /usr/bin/install -m 0644 -- "${ROOT}/deploy/sysctl-pgw.conf" "${config}"
    cmp -s "${ROOT}/deploy/sysctl-pgw.conf" "${config}" \
        || { printf 'repository PGW sysctl config fixture copy changed\n' >&2; exit 1; }
    PGW_FAKE_ROOT="${fixture}" "${command}" restart systemd-sysctl.service
    [[ "$(awk -F '\t' '$1=="systemd-sysctl.service" {print $3}' "${fixture}/runtime/services")" == active &&
       "$(tr -d '[:space:]' <"${fixture}/runtime/ip-forward")" == 1 ]] \
        || { printf 'repository PGW sysctl config was not applied\n' >&2; exit 1; }

    reset_fake_sysctl_contract_state "${fixture}" "${command}"
    printf 'net.ipv4.ip_forward = 1\nnet.ipv4.ip_forward = 0\n' >"${config}"
    PGW_FAKE_ROOT="${fixture}" "${command}" restart systemd-sysctl.service
    [[ "$(awk -F '\t' '$1=="systemd-sysctl.service" {print $3}' "${fixture}/runtime/services")" == active &&
       "$(tr -d '[:space:]' <"${fixture}/runtime/ip-forward")" == 0 ]] \
        || { printf 'PGW sysctl last active assignment did not win\n' >&2; exit 1; }

    printf 'net.ipv4.ip_forward = 1\nnet.ipv4.ip_forward = malformed\n' >"${config}"
    chmod 0644 "${config}"
    assert_fake_sysctl_rejected "${fixture}" "${command}" malformed "${external_digest}"
    printf 'net.ipv4.ip_forward = 1\n' >"${config}"
    chmod 0664 "${config}"
    assert_fake_sysctl_rejected "${fixture}" "${command}" group-writable "${external_digest}"
    rm -f -- "${config}"
    ln "${external}" "${config}"
    assert_fake_sysctl_rejected "${fixture}" "${command}" hardlink "${external_digest}"
    rm -f -- "${config}"
    ln -s "${external}" "${config}"
    assert_fake_sysctl_rejected "${fixture}" "${command}" symlink "${external_digest}"
    rm -f -- "${config}"
    mkfifo "${config}"
    assert_fake_sysctl_rejected "${fixture}" "${command}" special "${external_digest}" 3
    rm -f -- "${config}"
    # The fake's EUID check still rejects foreign ownership. Constructing that
    # node requires privilege and is unavailable in this non-root contract.
}

reset_fake_nft_contract_state() {
    local fixture="$1" command="$2"
    PGW_FAKE_ROOT="${fixture}" "${command}" stop nftables.service
    printf '0\n' >"${fixture}/runtime/ip-forward"
    printf 'table inet pgw_base { chain contract_baseline { } }\n' >"${fixture}/runtime/ruleset.nft"
    chmod 0644 "${fixture}/runtime/ruleset.nft"
    [[ "$(awk -F '\t' '$1=="nftables.service" {print $3}' "${fixture}/runtime/services")" == inactive &&
       "$(tr -d '[:space:]' <"${fixture}/runtime/ip-forward")" == 0 ]]
}

install_valid_nft_contract_files() {
    local fixture="$1" main base
    main="${fixture}/system/etc/nftables.conf"
    base="${fixture}/system/etc/nftables.d/pgw-base.nft"
    rm -f -- "${main}" "${base}"
    /usr/bin/install -m 0644 -- "${ROOT}/deploy/nftables.conf" "${main}"
    printf 'table inet pgw_base { chain forward { type filter hook forward priority filter; policy drop; } }\n' \
        >"${base}"
    chmod 0644 "${base}"
}

assert_fake_nft_rejected() {
    local fixture="$1" command="$2" label="$3" external_main_digest="$4" external_base_digest="$5"
    local operation="${6:-restart}" timeout_seconds="${7:-}" rc runtime_digest
    [[ "${operation}" == start || "${operation}" == restart ]] \
        || { printf 'invalid fake nftables test operation\n' >&2; exit 1; }
    reset_fake_nft_contract_state "${fixture}" "${command}"
    runtime_digest="$(/usr/bin/sha256sum -- "${fixture}/runtime/ruleset.nft" | awk '{print $1}')"
    set +e
    if [[ -n "${timeout_seconds}" ]]; then
        PGW_FAKE_ROOT="${fixture}" /usr/bin/timeout --signal=TERM --kill-after=1s \
            "${timeout_seconds}s" "${command}" "${operation}" nftables.service >/dev/null 2>&1
    else
        PGW_FAKE_ROOT="${fixture}" "${command}" "${operation}" nftables.service >/dev/null 2>&1
    fi
    rc=$?
    set -e
    [[ "${rc}" == 2 ]] \
        || { printf '%s nftables rejection returned rc=%s, expected rc=2\n' "${label}" "${rc}" >&2; exit 1; }
    [[ "$(awk -F '\t' '$1=="nftables.service" {print $3}' "${fixture}/runtime/services")" == inactive &&
       "$(tr -d '[:space:]' <"${fixture}/runtime/ip-forward")" == 0 ]] \
        || { printf '%s nftables rejection changed service/forwarding state\n' "${label}" >&2; exit 1; }
    [[ "$(/usr/bin/sha256sum -- "${fixture}/runtime/ruleset.nft" | awk '{print $1}')" == "${runtime_digest}" ]] \
        || { printf '%s nftables rejection changed runtime ruleset\n' "${label}" >&2; exit 1; }
    [[ "$(/usr/bin/sha256sum -- "${fixture}/outside-nft-main" | awk '{print $1}')" == "${external_main_digest}" &&
       "$(/usr/bin/sha256sum -- "${fixture}/outside-nft-base" | awk '{print $1}')" == "${external_base_digest}" ]] \
        || { printf '%s nftables rejection changed external sentinel\n' "${label}" >&2; exit 1; }
}

assert_fake_nft_contract() {
    local fixture="${temp_root}/fake-nft-contract" systemctl_command nft_command lifecycle_command
    local main base runtime inline expected external_main external_base external_main_digest external_base_digest before_digest
    local prior_base_digest prior_runtime_digest rc
    make_fixture "${fixture}" inactive
    systemctl_command="${fixture}/fake-bin/systemctl"
    nft_command="${fixture}/fake-bin/nft"
    lifecycle_command="${fixture}/fake-bin/lifecycle"
    main="${fixture}/system/etc/nftables.conf"
    base="${fixture}/system/etc/nftables.d/pgw-base.nft"
    runtime="${fixture}/runtime/ruleset.nft"
    external_main="${fixture}/outside-nft-main"
    external_base="${fixture}/outside-nft-base"
    /usr/bin/install -m 0644 -- "${ROOT}/deploy/nftables.conf" "${external_main}"
    printf '# external nft main sentinel\n' >>"${external_main}"
    printf 'table inet pgw_base { chain forward { type filter hook forward priority filter; policy drop; } }\n' \
        >"${external_base}"
    chmod 0644 "${external_base}"
    external_main_digest="$(/usr/bin/sha256sum -- "${external_main}" | awk '{print $1}')"
    external_base_digest="$(/usr/bin/sha256sum -- "${external_base}" | awk '{print $1}')"
    [[ "${external_main_digest}" =~ ^[0-9a-f]{64}$ && "${external_base_digest}" =~ ^[0-9a-f]{64}$ ]]

    printf 'prior persisted base\n' >"${base}"
    printf 'prior runtime ruleset\n' >"${runtime}"
    chmod 0644 "${base}" "${runtime}"
    prior_base_digest="$(/usr/bin/sha256sum -- "${base}" | awk '{print $1}')"
    prior_runtime_digest="$(/usr/bin/sha256sum -- "${runtime}" | awk '{print $1}')"
    set +e
    PGW_FAKE_NFT_INSTALL_FAIL_AT=after_base PGW_FAKE_ROOT="${fixture}" \
        "${lifecycle_command}" install-base >/dev/null 2>&1
    rc=$?
    set -e
    [[ "${rc}" == 2 ]] || { printf 'fake install-base injection returned %s, expected 2\n' "${rc}" >&2; exit 1; }
    [[ "$(/usr/bin/sha256sum -- "${base}" | awk '{print $1}')" == "${prior_base_digest}" &&
       "$(/usr/bin/sha256sum -- "${runtime}" | awk '{print $1}')" == "${prior_runtime_digest}" ]] \
        || { printf 'fake install-base failure did not restore prior pair\n' >&2; exit 1; }
    if find "${fixture}/system/etc/nftables.d" "${fixture}/runtime" -maxdepth 1 \
        \( -name '.pgw-base.candidate.*' -o -name '.pgw-base.*.new.*' -o -name '.pgw-base.*.backup.*' \
           -o -name '.ruleset.nft.new.*' -o -name '.ruleset.nft.backup.*' \) -print -quit | grep -q .; then
        printf 'fake install-base failure left publication residue\n' >&2
        exit 1
    fi

    rm -f -- "${base}"
    prior_runtime_digest="$(/usr/bin/sha256sum -- "${runtime}" | awk '{print $1}')"
    set +e
    PGW_FAKE_NFT_INSTALL_FAIL_AT=after_base PGW_FAKE_ROOT="${fixture}" \
        "${lifecycle_command}" install-base >/dev/null 2>&1
    rc=$?
    set -e
    [[ "${rc}" == 2 && ! -e "${base}" && ! -L "${base}" &&
       "$(/usr/bin/sha256sum -- "${runtime}" | awk '{print $1}')" == "${prior_runtime_digest}" ]] \
        || { printf 'fake install-base failure did not remove newly published base\n' >&2; exit 1; }

    PGW_FAKE_ROOT="${fixture}" "${lifecycle_command}" install-base
    [[ "$(/usr/bin/stat -c '%u:%a:%F:%h' -- "${base}")" == "${EUID}:644:regular file:1" &&
       "$(/usr/bin/stat -c '%u:%a:%F:%h' -- "${runtime}")" == "${EUID}:644:regular file:1" ]] \
        || { printf 'fake install-base published unsafe fixture files\n' >&2; exit 1; }
    cmp -s "${base}" "${runtime}" || { printf 'fake install-base base/runtime differ\n' >&2; exit 1; }
    /usr/bin/install -m 0644 -- "${ROOT}/deploy/nftables.conf" "${main}"

    reset_fake_nft_contract_state "${fixture}" "${systemctl_command}"
    before_digest="$(/usr/bin/sha256sum -- "${runtime}" | awk '{print $1}')"
    PGW_FAKE_ROOT="${fixture}" "${nft_command}" -c -f "${main}"
    [[ "$(/usr/bin/sha256sum -- "${runtime}" | awk '{print $1}')" == "${before_digest}" ]] \
        || { printf 'fake nft syntax check mutated runtime\n' >&2; exit 1; }
    PGW_FAKE_ROOT="${fixture}" "${systemctl_command}" restart nftables.service
    [[ "$(awk -F '\t' '$1=="nftables.service" {print $3}' "${fixture}/runtime/services")" == active ]] \
        || { printf 'fake nftables restart did not activate service\n' >&2; exit 1; }
    cmp -s "${base}" "${runtime}" || { printf 'fake nftables restart did not expand persisted base\n' >&2; exit 1; }

    rm -f -- "${main}" "${base}"
    before_digest="$(/usr/bin/sha256sum -- "${runtime}" | awk '{print $1}')"
    PGW_FAKE_ROOT="${fixture}" "${systemctl_command}" start nftables.service
    [[ "$(awk -F '\t' '$1=="nftables.service" {print $3}' "${fixture}/runtime/services")" == active &&
       "$(/usr/bin/sha256sum -- "${runtime}" | awk '{print $1}')" == "${before_digest}" &&
       "$(tr -d '[:space:]' <"${fixture}/runtime/ip-forward")" == 0 ]] \
        || { printf 'active fake nftables start was not a no-op\n' >&2; exit 1; }

    inline="${fixture}/backups/inline-restore.nft"
    expected="${fixture}/backups/inline-expected.nft"
    printf 'flush ruleset\ntable inet pgw_base { chain restored { } }\n' >"${inline}"
    printf 'table inet pgw_base { chain restored { } }\n' >"${expected}"
    reset_fake_nft_contract_state "${fixture}" "${systemctl_command}"
    before_digest="$(/usr/bin/sha256sum -- "${runtime}" | awk '{print $1}')"
    PGW_FAKE_ROOT="${fixture}" "${nft_command}" -c -f "${inline}"
    [[ "$(/usr/bin/sha256sum -- "${runtime}" | awk '{print $1}')" == "${before_digest}" ]] \
        || { printf 'inline restore syntax check mutated runtime\n' >&2; exit 1; }
    PGW_FAKE_ROOT="${fixture}" "${nft_command}" -f "${inline}"
    cmp -s "${expected}" "${runtime}" || { printf 'inline restore ruleset was not applied\n' >&2; exit 1; }

    install_valid_nft_contract_files "${fixture}"
    rm -f -- "${main}"
    assert_fake_nft_rejected "${fixture}" "${systemctl_command}" missing-main "${external_main_digest}" "${external_base_digest}" start

    install_valid_nft_contract_files "${fixture}"
    printf 'include "/etc/nftables.d/pgw-base.nft"\n' >"${main}"
    assert_fake_nft_rejected "${fixture}" "${systemctl_command}" malformed-main "${external_main_digest}" "${external_base_digest}"
    install_valid_nft_contract_files "${fixture}"
    printf 'flush ruleset\ninclude "/etc/nftables.d/pgw-base.nft"\ninclude "/etc/nftables.d/pgw-base.nft"\n' >"${main}"
    assert_fake_nft_rejected "${fixture}" "${systemctl_command}" duplicate-include "${external_main_digest}" "${external_base_digest}"
    install_valid_nft_contract_files "${fixture}"
    printf 'flush ruleset\ninclude "/etc/nftables.d/*.nft"\n' >"${main}"
    assert_fake_nft_rejected "${fixture}" "${systemctl_command}" glob-include "${external_main_digest}" "${external_base_digest}"
    install_valid_nft_contract_files "${fixture}"
    printf 'flush ruleset\ninclude "/etc/nftables.d/nested/pgw-base.nft"\n' >"${main}"
    assert_fake_nft_rejected "${fixture}" "${systemctl_command}" nested-include "${external_main_digest}" "${external_base_digest}"
    install_valid_nft_contract_files "${fixture}"
    printf 'flush ruleset\ninclude "/etc/nftables.d/pgw\\x2dbase.nft"\n' >"${main}"
    assert_fake_nft_rejected "${fixture}" "${systemctl_command}" escaped-include "${external_main_digest}" "${external_base_digest}"
    install_valid_nft_contract_files "${fixture}"
    printf 'flush ruleset\nadd table inet extra\ninclude "/etc/nftables.d/pgw-base.nft"\n' >"${main}"
    assert_fake_nft_rejected "${fixture}" "${systemctl_command}" unexpected-main "${external_main_digest}" "${external_base_digest}"
    install_valid_nft_contract_files "${fixture}"
    printf 'flush ruleset\r\ninclude "/etc/nftables.d/pgw-base.nft"\r\n' >"${main}"
    assert_fake_nft_rejected "${fixture}" "${systemctl_command}" carriage-return-main "${external_main_digest}" "${external_base_digest}"
    install_valid_nft_contract_files "${fixture}"
    printf 'flush\xC2\xA0ruleset\ninclude "/etc/nftables.d/pgw-base.nft"\n' >"${main}"
    assert_fake_nft_rejected "${fixture}" "${systemctl_command}" unicode-whitespace-main "${external_main_digest}" "${external_base_digest}"
    install_valid_nft_contract_files "${fixture}"
    printf 'flush ruleset\xE2\x80\xA8include "/etc/nftables.d/pgw-base.nft"\n' >"${main}"
    assert_fake_nft_rejected "${fixture}" "${systemctl_command}" unicode-separator-main "${external_main_digest}" "${external_base_digest}"
    install_valid_nft_contract_files "${fixture}"
    printf 'flush \xFFruleset\ninclude "/etc/nftables.d/pgw-base.nft"\n' >"${main}"
    assert_fake_nft_rejected "${fixture}" "${systemctl_command}" malformed-utf8-main "${external_main_digest}" "${external_base_digest}"

    install_valid_nft_contract_files "${fixture}"
    chmod 0664 "${main}"
    assert_fake_nft_rejected "${fixture}" "${systemctl_command}" group-writable-main "${external_main_digest}" "${external_base_digest}"
    install_valid_nft_contract_files "${fixture}"
    rm -f -- "${main}"; ln "${external_main}" "${main}"
    assert_fake_nft_rejected "${fixture}" "${systemctl_command}" hardlink-main "${external_main_digest}" "${external_base_digest}"
    install_valid_nft_contract_files "${fixture}"
    rm -f -- "${main}"; ln -s "${external_main}" "${main}"
    assert_fake_nft_rejected "${fixture}" "${systemctl_command}" symlink-main "${external_main_digest}" "${external_base_digest}"
    install_valid_nft_contract_files "${fixture}"
    rm -f -- "${main}"; mkfifo "${main}"
    assert_fake_nft_rejected "${fixture}" "${systemctl_command}" fifo-main "${external_main_digest}" "${external_base_digest}" restart 3

    install_valid_nft_contract_files "${fixture}"
    rm -f -- "${base}"
    assert_fake_nft_rejected "${fixture}" "${systemctl_command}" missing-base "${external_main_digest}" "${external_base_digest}"
    install_valid_nft_contract_files "${fixture}"
    printf 'table inet other { }\n' >"${base}"
    assert_fake_nft_rejected "${fixture}" "${systemctl_command}" malformed-base "${external_main_digest}" "${external_base_digest}"
    install_valid_nft_contract_files "${fixture}"
    printf 'table inet pgw_base { }\n' >"${base}"
    assert_fake_nft_rejected "${fixture}" "${systemctl_command}" empty-pgw-base "${external_main_digest}" "${external_base_digest}"
    install_valid_nft_contract_files "${fixture}"
    printf 'table inet pgw_base { chain forward { type filter hook forward priority filter; policy accept; } }\n' >"${base}"
    assert_fake_nft_rejected "${fixture}" "${systemctl_command}" policy-accept-base "${external_main_digest}" "${external_base_digest}"
    install_valid_nft_contract_files "${fixture}"
    printf 'table inet pgw_base { chain forward { type filter hook forward priority filter; policy drop; }\n' >"${base}"
    assert_fake_nft_rejected "${fixture}" "${systemctl_command}" unclosed-marker-base "${external_main_digest}" "${external_base_digest}"
    install_valid_nft_contract_files "${fixture}"
    printf 'delete table inet pgw_base\ntable inet pgw_base { chain forward { type filter hook forward priority filter; policy drop; } }\n' >"${base}"
    assert_fake_nft_rejected "${fixture}" "${systemctl_command}" delete-command-base "${external_main_digest}" "${external_base_digest}"
    install_valid_nft_contract_files "${fixture}"
    printf 'add table inet pgw_base\n' >"${base}"
    assert_fake_nft_rejected "${fixture}" "${systemctl_command}" add-command-base "${external_main_digest}" "${external_base_digest}"
    install_valid_nft_contract_files "${fixture}"
    printf 'table inet pgw_base { chain forward { type filter hook forward priority filter; policy drop; } }\ntable inet extra { }\n' >"${base}"
    assert_fake_nft_rejected "${fixture}" "${systemctl_command}" extra-table-base "${external_main_digest}" "${external_base_digest}"
    install_valid_nft_contract_files "${fixture}"
    printf 'table inet pgw_base { chain forward { type filter hook forward priority filter; policy drop; } }\nbogus trailing command\n' >"${base}"
    assert_fake_nft_rejected "${fixture}" "${systemctl_command}" trailing-command-base "${external_main_digest}" "${external_base_digest}"
    install_valid_nft_contract_files "${fixture}"
    printf 'flush ruleset\ntable inet pgw_base { }\n' >"${base}"
    assert_fake_nft_rejected "${fixture}" "${systemctl_command}" base-flush "${external_main_digest}" "${external_base_digest}"
    install_valid_nft_contract_files "${fixture}"
    printf 'table inet pgw_base { }\ninclude "/etc/nftables.d/extra.nft"\n' >"${base}"
    assert_fake_nft_rejected "${fixture}" "${systemctl_command}" base-include "${external_main_digest}" "${external_base_digest}"
    install_valid_nft_contract_files "${fixture}"
    chmod 0664 "${base}"
    assert_fake_nft_rejected "${fixture}" "${systemctl_command}" group-writable-base "${external_main_digest}" "${external_base_digest}" start
    install_valid_nft_contract_files "${fixture}"
    rm -f -- "${base}"; ln "${external_base}" "${base}"
    assert_fake_nft_rejected "${fixture}" "${systemctl_command}" hardlink-base "${external_main_digest}" "${external_base_digest}"
    install_valid_nft_contract_files "${fixture}"
    rm -f -- "${base}"; ln -s "${external_base}" "${base}"
    assert_fake_nft_rejected "${fixture}" "${systemctl_command}" symlink-base "${external_main_digest}" "${external_base_digest}"
    install_valid_nft_contract_files "${fixture}"
    rm -f -- "${base}"; mkfifo "${base}"
    assert_fake_nft_rejected "${fixture}" "${systemctl_command}" fifo-base "${external_main_digest}" "${external_base_digest}" restart 3
    rm -f -- "${main}" "${base}"
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


def identity(info):
    return info.st_dev, info.st_ino


def remove_tree(parent_fd, entry_name, expected_info=None):
    listed = os.stat(entry_name, dir_fd=parent_fd, follow_symlinks=False)
    if expected_info is not None and identity(listed) != identity(expected_info):
        raise SystemExit("sealed UI cleanup entry identity changed")
    if not stat.S_ISDIR(listed.st_mode):
        if listed.st_uid != expected or stat.S_IMODE(listed.st_mode) & 0o022:
            raise SystemExit("unsafe sealed UI cleanup entry")
        os.unlink(entry_name, dir_fd=parent_fd)
        return

    child_fd = os.open(entry_name, flags, dir_fd=parent_fd)
    try:
        opened = os.fstat(child_fd)
        if (identity(opened) != identity(listed) or opened.st_uid != expected or
                stat.S_IMODE(opened.st_mode) & 0o022):
            raise SystemExit("unsafe sealed UI cleanup directory")
        for child_name in os.listdir(child_fd):
            if not child_name or child_name in (".", "..") or "/" in child_name or "\x00" in child_name:
                raise SystemExit("unsafe sealed UI cleanup entry name")
            remove_tree(child_fd, child_name)
        os.fsync(child_fd)
    finally:
        os.close(child_fd)

    rebound = os.stat(entry_name, dir_fd=parent_fd, follow_symlinks=False)
    if identity(rebound) != identity(opened):
        raise SystemExit("sealed UI cleanup directory identity changed")
    os.rmdir(entry_name, dir_fd=parent_fd)


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
    remove_tree(temp_fd, name, case_info)
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

assert_capture_recoverability_gate() {
    local fixture="$1" snapshot="$2" expected_verify_count="$3" stage
    local materialize_stats metadata_stats verify_stats cleanup_stats
    local materialize_line metadata_line verify_line cleanup_line
    stage="${fixture}/system/run/pgw/snapshot-validation.$(basename -- "${snapshot}")"
    materialize_stats="$(awk -v command='snapshot_payload.py materialize' -v stage="${stage}" \
        'index($0,command) && index($0,stage) {count++; line=NR} END {print count+0 ":" line+0}' \
        "${fixture}/commands.log")"
    metadata_stats="$(awk -v command="restore_snapshot.py metadata ${stage}" \
        'index($0,command) {count++; line=NR} END {print count+0 ":" line+0}' \
        "${fixture}/commands.log")"
    verify_stats="$(awk -v command="restore_snapshot.py verify ${stage} payload ${fixture}/system" \
        'index($0,command) {count++; line=NR} END {print count+0 ":" line+0}' \
        "${fixture}/commands.log")"
    cleanup_stats="$(awk -v command="snapshot_payload.py remove-stage ${stage} ${EUID}" \
        'index($0,command) {count++; line=NR} END {print count+0 ":" line+0}' \
        "${fixture}/commands.log")"
    [[ "${materialize_stats%%:*}" == 1 && "${metadata_stats%%:*}" == 1 &&
       "${verify_stats%%:*}" == "${expected_verify_count}" && "${cleanup_stats%%:*}" == 1 ]]
    materialize_line="${materialize_stats#*:}"
    metadata_line="${metadata_stats#*:}"
    verify_line="${verify_stats#*:}"
    cleanup_line="${cleanup_stats#*:}"
    ((materialize_line < metadata_line && metadata_line < cleanup_line))
    if ((expected_verify_count == 1)); then
        ((metadata_line < verify_line && verify_line < cleanup_line))
    fi
    [[ ! -e "${stage}" && ! -L "${stage}" ]] \
        || { printf 'snapshot recoverability validation left plaintext residue\n' >&2; return 1; }
}

print_bounded_fixture_evidence() {
    /usr/bin/python3 -I - "$1" <<'PY'
import os
import stat
import sys
import unicodedata

LIMIT = 65536
NAMES = ("lifecycle-transcript.tsv", "commands.log", "installer.log")
MARKER = "[missing or unsafe evidence file]"


def emit(name, message):
    sys.stderr.write(f"[fixture-evidence:{name}] {message}\n")


def sanitize(payload):
    text = payload.decode("utf-8", "backslashreplace")
    safe = []
    for character in text:
        if character in ("\n", "\t"):
            safe.append(character)
            continue
        category = unicodedata.category(character)
        if category.startswith("C") or category in ("Zl", "Zp"):
            codepoint = ord(character)
            safe.append(f"\\u{codepoint:04x}" if codepoint <= 0xffff else f"\\U{codepoint:08x}")
        else:
            safe.append(character)
    return "".join(safe)


def admitted_file(info, expected_uid):
    return (stat.S_ISREG(info.st_mode) and info.st_uid == expected_uid
            and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) & 0o022 == 0)


def stable_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def name_binds(directory, name, info):
    bound = os.stat(name, dir_fd=directory, follow_symlinks=False)
    return (bound.st_dev, bound.st_ino) == (info.st_dev, info.st_ino)


fixture = sys.argv[1]
directory = -1
try:
    if not os.path.isabs(fixture) or os.path.normpath(fixture) != fixture:
        raise ValueError("unsafe fixture directory")
    directory = os.open(fixture, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    directory_info = os.fstat(directory)
    if (not stat.S_ISDIR(directory_info.st_mode)
            or directory_info.st_uid != os.geteuid()
            or stat.S_IMODE(directory_info.st_mode) & 0o022):
        raise ValueError("unsafe fixture directory")
except (OSError, ValueError):
    for basename in NAMES:
        emit(basename, MARKER)
else:
    for basename in NAMES:
        descriptor = -1
        payload = None
        try:
            descriptor = os.open(
                basename,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                dir_fd=directory,
            )
            before = os.fstat(descriptor)
            if not admitted_file(before, os.geteuid()) or not name_binds(directory, basename, before):
                raise ValueError("unsafe evidence file")
            os.lseek(descriptor, max(0, before.st_size - LIMIT), os.SEEK_SET)
            chunks = []
            remaining = LIMIT
            while remaining:
                chunk = os.read(descriptor, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            after = os.fstat(descriptor)
            if (not admitted_file(after, os.geteuid())
                    or stable_identity(after) != stable_identity(before)
                    or not name_binds(directory, basename, after)):
                raise ValueError("evidence file changed")
            payload = b"".join(chunks)
        except (OSError, ValueError):
            payload = None
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if payload is None:
            emit(basename, MARKER)
            continue
        emit(basename, "--- last at most 65536 bytes ---")
        text = sanitize(payload)
        if not text:
            emit(basename, "[empty evidence file]")
            continue
        lines = text.split("\n")
        if text.endswith("\n"):
            lines.pop()
        for line in lines:
            emit(basename, line)
finally:
    if directory >= 0:
        os.close(directory)
PY
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
    printf 'verified launcher descriptor accepts legacy migration preflight\n'
    fixture="${temp_root}/verified-api-descriptor"
    make_fixture "${fixture}" active
    printf '{"proxies":{},"clients":{},"mappings":{}}\n' >"${fixture}/system/var/lib/pgw/state.json"
    rc="$(run_failure "${fixture}" verified_api_descriptor)"
    [[ "${rc}" == 0 ]] || {
        printf 'verified descriptor preflight returned %s\n' "${rc}" >&2
        print_bounded_fixture_evidence "${fixture}"
        exit 1
    }
    grep -Fq 'legacy state dry-run passed' "${fixture}/installer.log" || {
        printf 'verified descriptor preflight did not report legacy validation\n' >&2
        cat "${fixture}/installer.log" >&2
        exit 1
    }
    printf 'unmapped launcher descriptor is rejected by legacy preflight\n'
    fixture="${temp_root}/rejected-api-descriptor"
    make_fixture "${fixture}" active
    printf '{"proxies":{},"clients":{},"mappings":{}}\n' >"${fixture}/system/var/lib/pgw/state.json"
    rc="$(run_failure "${fixture}" rejected_api_descriptor)"
    [[ "${rc}" == 1 ]] || {
        printf 'unmapped descriptor preflight returned %s\n' "${rc}" >&2
        print_bounded_fixture_evidence "${fixture}"
        exit 1
    }
    grep -Fq 'staged pgw-api migration binary is unavailable' "${fixture}/installer.log" || {
        printf 'unmapped descriptor did not fail the migration preflight\n' >&2
        cat "${fixture}/installer.log" >&2
        exit 1
    }
    printf 'nftables include-aware fixture fidelity\n'
    assert_fake_nft_contract
    printf 'systemd-sysctl absent/present fixture fidelity\n'
    assert_fake_sysctl_contract
    printf 'test-only root restore-authority admission\n'
    assert_restore_authority_contract
    printf 'non-root sealed UI encrypted materialization\n'
    assert_nonroot_sealed_ui_materialize
    printf 'successful upgrade and explicit rollback rehearsal\n'
    fixture="${temp_root}/success-rollback"
    make_fixture "${fixture}" active
    [[ ! -e "${fixture}/expected-system/etc/sysctl.d/99-pgw.conf" &&
       ! -L "${fixture}/expected-system/etc/sysctl.d/99-pgw.conf" ]]
    rc="$(run_failure "${fixture}" success_rollback)"
    [[ "${rc}" == 0 ]] || {
        printf 'successful upgrade/rollback rehearsal returned %s\n' "${rc}" >&2
        print_bounded_fixture_evidence "${fixture}"
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
    assert_capture_recoverability_gate "${fixture}" "${snapshot}" 1
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
    if [[ "${boundary}" == after_snapshot ]]; then
        printf 'net.ipv4.ip_forward = 1\n' >"${fixture}/system/etc/sysctl.d/99-pgw.conf"
        chmod 0644 "${fixture}/system/etc/sysctl.d/99-pgw.conf"
        cp -a -- "${fixture}/system/etc/sysctl.d/99-pgw.conf" \
            "${fixture}/expected-system/etc/sysctl.d/99-pgw.conf"
    fi
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
    if [[ "${boundary}" == after_snapshot ]]; then
        cmp -s "${fixture}/expected-system/etc/sysctl.d/99-pgw.conf" \
            "${fixture}/system/etc/sysctl.d/99-pgw.conf" \
            || { printf 'present PGW sysctl config was not restored\n' >&2; exit 1; }
    fi
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
  cleanup_writable_dirs=(
      "${fixture}/system/usr/local/share/pgw/web"
      "${fixture}/system/usr/local/share/pgw/web/static"
      "${fixture}/expected-system/usr/local/share/pgw/web"
      "${fixture}/expected-system/usr/local/share/pgw/web/static"
  )
  chmod 0440 "${fixture}/system/usr/local/share/pgw/web/static/"*
  chmod 0550 "${fixture}/system/usr/local/share/pgw/web/static" \
      "${fixture}/system/usr/local/share/pgw/web"
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
  assert_capture_recoverability_gate "${fixture}" "${capture_snapshot}" 0
  [[ ! -e "${fixture}/system/var/lib/pgw-lifecycle/recovery.journal" ]]
  ! grep -Eq 'python3 .*restore_snapshot.py verify ' "${fixture}/commands.log"
  make_registered_cleanup_dirs_writable
  cleanup_writable_dirs=()

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
      assert_capture_recoverability_gate "${fixture}" "${capture_snapshot}" 1
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

  for validation_crash_point in materialized metadata verified; do
      printf 'snapshot validation plaintext crash recovery: %s\n' "${validation_crash_point}"
      fixture="${temp_root}/validation-crash-${validation_crash_point}"
      make_fixture "${fixture}" active
      validation_sibling="${fixture}/system/run/pgw/snapshot-validation.not-snapshot"
      install -d -m 0700 "${validation_sibling}"
      printf 'validation sibling canary\n' >"${validation_sibling}/canary"
      cp -a -- "${validation_sibling}" \
          "${fixture}/expected-system/run/pgw/snapshot-validation.not-snapshot"
      sibling_digest="$(sha256sum "${validation_sibling}/canary" | awk '{print $1}')"
      rc="$(run_failure "${fixture}" "crash_validation:${validation_crash_point}")"
      [[ "${rc}" == 137 ]] || {
          printf 'snapshot validation crash %s returned %s, wanted 137\n' \
              "${validation_crash_point}" "${rc}" >&2
          cat "${fixture}/installer.log" >&2
          exit 1
      }
      journal="${fixture}/system/var/lib/pgw-lifecycle/recovery.journal"
      [[ -f "${journal}" && ! -L "${journal}" ]]
      grep -Fxq 'phase=capturing' "${journal}"
      snapshot="$(sed -n 's/^snapshot=//p' "${journal}")"
      validation_stage="${fixture}/system/run/pgw/snapshot-validation.$(basename -- "${snapshot}")"
      [[ -d "${validation_stage}" && ! -L "${validation_stage}" &&
         "$(stat -c '%u:%a:%F' "${validation_stage}")" == "${EUID}:700:directory" &&
         -f "${validation_stage}/files/var/lib/pgw/pgw.db" &&
         ! -e "${snapshot}/snapshot.sha256" && ! -e "${snapshot}/snapshot.hmac" ]]
      case "${validation_crash_point}" in
          materialized) [[ ! -e "${validation_stage}/metadata.json" ]] ;;
          metadata|verified) [[ -f "${validation_stage}/metadata.json" &&
              ! -L "${validation_stage}/metadata.json" ]] ;;
      esac
      grep -Fq "snapshot-validation-crash:${validation_crash_point}" \
          "${fixture}/commands.log"
      [[ "$(sha256sum "${validation_sibling}/canary" | awk '{print $1}')" == \
          "${sibling_digest}" ]]
      recover_rc="$(run_failure "${fixture}" recover)"
      [[ "${recover_rc}" == 0 ]] || {
          printf 'snapshot validation crash recovery %s returned %s\n' \
              "${validation_crash_point}" "${recover_rc}" >&2
          cat "${fixture}/installer.log" >&2
          exit 1
      }
      [[ ! -e "${validation_stage}" && ! -L "${validation_stage}" && ! -e "${journal}" ]]
      [[ "$(sha256sum "${validation_sibling}/canary" | awk '{print $1}')" == \
          "${sibling_digest}" ]]
      diff -r --no-dereference "${fixture}/expected-system" "${fixture}/system"
      diff -r --no-dereference "${fixture}/expected-runtime" "${fixture}/runtime"
      grep -Fq 'state evidence only' "${fixture}/installer.log"
  done

  printf 'snapshot validation cleanup failure retains durable recovery evidence\n'
  fixture="${temp_root}/validation-cleanup-failure"
  make_fixture "${fixture}" active
  printf 'inject cleanup failure\n' >"${fixture}/fail-snapshot-validation-cleanup"
  chmod 0600 "${fixture}/fail-snapshot-validation-cleanup"
  rc="$(run_failure "${fixture}" after_services)"
  [[ "${rc}" == 125 ]] || {
      printf 'snapshot validation cleanup failure returned %s, wanted 125\n' "${rc}" >&2
      cat "${fixture}/installer.log" >&2
      exit 1
  }
  journal="${fixture}/system/var/lib/pgw-lifecycle/recovery.journal"
  [[ -f "${journal}" && ! -L "${journal}" ]]
  grep -Fxq 'phase=capturing' "${journal}"
  snapshot="$(sed -n 's/^snapshot=//p' "${journal}")"
  validation_stage="${fixture}/system/run/pgw/snapshot-validation.$(basename -- "${snapshot}")"
  [[ -d "${validation_stage}" && ! -L "${validation_stage}" &&
     -f "${validation_stage}/files/var/lib/pgw/pgw.db" &&
     ! -e "${snapshot}/snapshot.sha256" && ! -e "${snapshot}/snapshot.hmac" ]]
  [[ "$(tr -d '[:space:]' <"${fixture}/runtime/ip-forward")" == 0 ]]
  ! awk -F '\t' '$3=="active" {found=1} END {exit found?0:1}' "${fixture}/runtime/services"
  grep -Fq 'automatic rollback was partial or failed' "${fixture}/installer.log"
  rm -f -- "${fixture}/fail-snapshot-validation-cleanup"
  recover_rc="$(run_failure "${fixture}" recover)"
  [[ "${recover_rc}" == 0 ]] || {
      printf 'snapshot validation cleanup recovery returned %s\n' "${recover_rc}" >&2
      cat "${fixture}/installer.log" >&2
      exit 1
  }
  [[ ! -e "${validation_stage}" && ! -L "${validation_stage}" && ! -e "${journal}" ]]
  diff -r --no-dereference "${fixture}/expected-system" "${fixture}/system"
  diff -r --no-dereference "${fixture}/expected-runtime" "${fixture}/runtime"

  printf 'unsafe snapshot validation collision remains fail-closed across retries\n'
  fixture="${temp_root}/validation-collision-symlink"
  make_fixture "${fixture}" active
  validation_sibling="${fixture}/system/run/pgw/snapshot-validation.not-snapshot"
  install -d -m 0700 "${validation_sibling}"
  printf 'collision sibling canary\n' >"${validation_sibling}/canary"
  cp -a -- "${validation_sibling}" \
      "${fixture}/expected-system/run/pgw/snapshot-validation.not-snapshot"
  sibling_digest="$(sha256sum "${validation_sibling}/canary" | awk '{print $1}')"
  rc="$(run_failure "${fixture}" validation_collision:symlink)"
  [[ "${rc}" == 125 ]] || {
      printf 'snapshot validation collision returned %s, wanted 125\n' "${rc}" >&2
      cat "${fixture}/installer.log" >&2
      exit 1
  }
  journal="${fixture}/system/var/lib/pgw-lifecycle/recovery.journal"
  snapshot="$(sed -n 's/^snapshot=//p' "${journal}")"
  validation_stage="${fixture}/system/run/pgw/snapshot-validation.$(basename -- "${snapshot}")"
  [[ -L "${validation_stage}" && -f "${fixture}/outside-validation-sentinel" &&
     ! -L "${fixture}/outside-validation-sentinel" ]]
  outside_digest="$(sha256sum "${fixture}/outside-validation-sentinel" | awk '{print $1}')"
  [[ "$(tr -d '[:space:]' <"${fixture}/runtime/ip-forward")" == 0 ]]
  ! awk -F '\t' '$3=="active" {found=1} END {exit found?0:1}' "${fixture}/runtime/services"
  for retry in 1 2; do
      recover_rc="$(run_failure "${fixture}" recover)"
      [[ "${recover_rc}" == 125 && -L "${validation_stage}" && -f "${journal}" ]]
      [[ "$(sha256sum "${fixture}/outside-validation-sentinel" | awk '{print $1}')" == \
          "${outside_digest}" ]]
      [[ "$(sha256sum "${validation_sibling}/canary" | awk '{print $1}')" == \
          "${sibling_digest}" ]]
      [[ "$(tr -d '[:space:]' <"${fixture}/runtime/ip-forward")" == 0 ]]
      ! awk -F '\t' '$3=="active" {found=1} END {exit found?0:1}' "${fixture}/runtime/services"
  done
  rm -f -- "${validation_stage}"
  recover_rc="$(run_failure "${fixture}" recover)"
  [[ "${recover_rc}" == 0 ]] || {
      printf 'snapshot validation collision recovery returned %s\n' "${recover_rc}" >&2
      cat "${fixture}/installer.log" >&2
      exit 1
  }
  [[ ! -e "${validation_stage}" && ! -L "${validation_stage}" && ! -e "${journal}" ]]
  [[ "$(sha256sum "${fixture}/outside-validation-sentinel" | awk '{print $1}')" == \
      "${outside_digest}" ]]
  [[ "$(sha256sum "${validation_sibling}/canary" | awk '{print $1}')" == \
      "${sibling_digest}" ]]
  diff -r --no-dereference "${fixture}/expected-system" "${fixture}/system"
  diff -r --no-dereference "${fixture}/expected-runtime" "${fixture}/runtime"
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
    printf '{"proxies":{},"clients":{},"mappings":{}}\n' >"${crash_fixture}/system/var/lib/pgw/state.json"
    cp -- "${crash_fixture}/system/var/lib/pgw/state.json" "${crash_fixture}/expected-system/var/lib/pgw/state.json"
    # crash_legacy_post_import runs the real import subprocess against this
    # file with the production sqlite driver. make_fixture's placeholder text
    # is not a valid database; truncate to empty so modernc.org/sqlite
    # initializes it fresh, exactly like a real first install would.
    : >"${crash_fixture}/system/var/lib/pgw/pgw.db"
    cp -- "${crash_fixture}/system/var/lib/pgw/pgw.db" "${crash_fixture}/expected-system/var/lib/pgw/pgw.db"
    crash_rc="$(run_failure "${crash_fixture}" "${legacy_crash}")"
    [[ "${crash_rc}" == 137 ]] || { printf 'legacy sealed crash returned %s, wanted 137\n' "${crash_rc}" >&2; cat "${crash_fixture}/installer.log" >&2; exit 1; }
    journal="${crash_fixture}/system/var/lib/pgw-lifecycle/recovery.journal"
    snapshot="$(sed -n 's/^snapshot=//p' "${journal}")"
    [[ -f "${journal}" && "${snapshot}" == "${crash_fixture}/backups"/install.* ]] || {
        printf 'legacy sealed crash journal contract failed: boundary=%s journal=%s snapshot=%s\n' \
            "${legacy_crash}" "$(test -f "${journal}" && printf present || printf absent)" "${snapshot:-missing}" >&2
        exit 1
    }
    sealed_stage="${crash_fixture}/system/run/pgw/legacy-sealed.$(basename -- "${snapshot}")"
    [[ -d "${sealed_stage}" && ! -L "${sealed_stage}" ]] || {
        printf 'legacy sealed crash stage contract failed: boundary=%s stage=%s directory=%s symlink=%s\n' \
            "${legacy_crash}" "${sealed_stage}" "$(test -d "${sealed_stage}" && printf yes || printf no)" \
            "$(test -L "${sealed_stage}" && printf yes || printf no)" >&2
        exit 1
    }
    if [[ "${legacy_crash}" == crash_legacy_post_import ]]; then
        [[ -f "${crash_fixture}/system/run/pgw/legacy-import/report.json" ]] || {
            printf 'legacy post-import crash report contract failed: report=%s\n' \
                "$(test -f "${crash_fixture}/system/run/pgw/legacy-import/report.json" && printf present || printf absent)" >&2
            exit 1
        }
    fi
    # A sibling is a no-delete canary: recovery may remove only the identity-
    # derived stage, never glob or recursively clean /run/pgw.
    mkdir -p "${crash_fixture}/system/run/pgw/legacy-sealed.not-snapshot"
    mkdir -p "${crash_fixture}/expected-system/run/pgw/legacy-sealed.not-snapshot"
    recover_rc="$(run_failure "${crash_fixture}" recover)"
    [[ "${recover_rc}" == 0 ]] || { printf 'legacy sealed recovery returned %s\n' "${recover_rc}" >&2; cat "${crash_fixture}/installer.log" >&2; exit 1; }
    [[ ! -e "${sealed_stage}" && -d "${crash_fixture}/system/run/pgw/legacy-sealed.not-snapshot" ]] || {
        printf 'legacy sealed recovery stage cleanup contract failed: stage_exists=%s sibling_directory=%s\n' \
            "$(test -e "${sealed_stage}" && printf yes || printf no)" \
            "$(test -d "${crash_fixture}/system/run/pgw/legacy-sealed.not-snapshot" && printf yes || printf no)" >&2
        exit 1
    }
    [[ ! -e "${crash_fixture}/system/run/pgw/legacy-import" ]] || {
        printf 'legacy sealed recovery report cleanup contract failed: runtime_exists=%s\n' \
            "$(test -e "${crash_fixture}/system/run/pgw/legacy-import" && printf yes || printf no)" >&2
        exit 1
    }
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
        printf '{"proxies":{},"clients":{},"mappings":{}}\n' >"${crash_fixture}/system/var/lib/pgw/state.json"
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
        printf '{"proxies":{},"clients":{},"mappings":{}}\n' >"${crash_fixture}/system/var/lib/pgw/state.json"
        cp -- "${crash_fixture}/system/var/lib/pgw/state.json" "${crash_fixture}/expected-system/var/lib/pgw/state.json"
        : >"${crash_fixture}/system/var/lib/pgw/pgw.db"
        cp -- "${crash_fixture}/system/var/lib/pgw/pgw.db" "${crash_fixture}/expected-system/var/lib/pgw/pgw.db"
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
