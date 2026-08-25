#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
readonly ROOT
readonly UNITS="${ROOT}/deploy/systemd"

fail() { printf 'deploy hardening test: %s\n' "$*" >&2; exit 1; }
assert_contains() { grep -Fqs -- "$2" "$1" || fail "${1#${ROOT}/} missing: $2"; }
assert_not_contains() { ! grep -Eqs -- "$2" "$1" || fail "${1#${ROOT}/} contains forbidden pattern: $2"; }

PYTHON3="$(command -v python3 || command -v python || true)"
readonly PYTHON3
[[ -n "${PYTHON3}" ]] || fail 'python3-compatible interpreter is required for structural evidence'

((EUID != 0)) || fail 'aggregate hardening must run unprivileged; run dedicated root evidence scripts separately'

while IFS= read -r script; do bash -n "${script}"; done < <(find "${ROOT}/deploy" -type f -name '*.sh' -print | sort)
bash -n "${ROOT}/update-pgw.sh"

while IFS= read -r backup; do
    [[ -e "${ROOT}/${backup}" ]] || continue
    if [[ -x "${ROOT}/${backup}" ]] || head -n1 "${ROOT}/${backup}" | grep -Eq '^#!.*(bash|/sh)([[:space:]]|$)'; then
        fail "tracked legacy backup remains executable: ${backup}"
    fi
done < <(git -C "${ROOT}" ls-files | grep -E '(\.bak($|\.)|\.backup($|\.)|pre-socks5$)' || true)

# A force-added cache/backup/build input must be rejected before a candidate
# source archive is produced; .gitignore alone is not a release boundary.
assert_contains "${ROOT}/deploy/build-release.sh" 'ls-tree -r --name-only'
assert_contains "${ROOT}/deploy/build-release.sh" '__pycache__/'
assert_contains "${ROOT}/deploy/build-release.sh" '[.]py[co]$'
assert_contains "${ROOT}/deploy/build-release.sh" '[.](bak|backup)'
assert_contains "${ROOT}/deploy/build-release.sh" 'build(/|$)'

for root_entrypoint in \
    "${ROOT}/deploy/install-pgw.sh" "${ROOT}/deploy/update-pgw.sh" \
    "${ROOT}/update-pgw.sh" "${ROOT}/deploy/install-pgw-base.sh" \
    "${ROOT}/deploy/pgw-verify-base.sh" "${ROOT}/deploy/tests/installer_harness.sh"; do
    [[ "$(head -n1 "${root_entrypoint}")" == '#!/bin/bash' ]] \
        || fail "${root_entrypoint#${ROOT}/} must use absolute /bin/bash"
done

assert_contains "${UNITS}/pgw-api.service" 'User=pgw-api'
assert_contains "${UNITS}/pgw-agent.service" 'User=pgw-agent'
assert_contains "${UNITS}/pgw-fwd@.service" 'User=pgw-fwd'
assert_contains "${UNITS}/pgw-ui.service" 'User=pgw-ui'
assert_contains "${UNITS}/pgw-health.service" 'User=pgw-health'
[[ ! -e "${ROOT}/deploy/pgw-webhook.service" ]] || fail 'legacy root webhook unit must not be shipped'
[[ ! -e "${ROOT}/cmd/webhook/main.go" ]] || fail 'legacy webhook executable source must not be shipped'
if find "${ROOT}/cmd/webhook" -type f -name '*.go' -print -quit 2>/dev/null | grep -q .; then
    fail 'cmd/webhook must not contain a buildable Go package'
fi
if (cd -- "${ROOT}" && go build ./cmd/webhook >/dev/null 2>&1); then
    fail 'legacy cmd/webhook unexpectedly remains buildable'
fi
! grep -Rqs '^User=root$' "${UNITS}" || fail 'a committed PGW application unit runs as root'

for unit in pgw-api.service pgw-fwd@.service pgw-ui.service pgw-health.service; do
    assert_contains "${UNITS}/${unit}" 'CapabilityBoundingSet='
    assert_contains "${UNITS}/${unit}" 'AmbientCapabilities='
    assert_not_contains "${UNITS}/${unit}" '^CapabilityBoundingSet=.+$|^AmbientCapabilities=.+$'
    assert_contains "${UNITS}/${unit}" 'NoNewPrivileges=yes'
    assert_contains "${UNITS}/${unit}" 'ProtectSystem=strict'
done
assert_contains "${UNITS}/pgw-agent.service" 'CapabilityBoundingSet=CAP_NET_ADMIN'
assert_contains "${UNITS}/pgw-agent.service" 'AmbientCapabilities=CAP_NET_ADMIN'
assert_not_contains "${UNITS}/pgw-agent.service" 'CAP_CHOWN|CAP_DAC_OVERRIDE'

assert_contains "${UNITS}/pgw-api.service" 'LoadCredential=jwt_secret:/etc/pgw/jwt_secret'
assert_contains "${UNITS}/pgw-api.service" 'LoadCredential=admin_pass_hash:/etc/pgw/admin_pass_hash'
assert_contains "${UNITS}/pgw-api.service" 'LoadCredential=secrets_key:/etc/pgw/secrets.key'
assert_contains "${UNITS}/pgw-api.service" 'LoadCredential=agent_service_token:/etc/pgw/agent.token'
assert_contains "${UNITS}/pgw-api.service" 'LoadCredential=ui_proxy_token:/etc/pgw/credentials-current/ui_proxy_token'
assert_contains "${UNITS}/pgw-agent.service" 'LoadCredential=agent_service_token:/etc/pgw/agent.token'
assert_contains "${UNITS}/pgw-fwd@.service" 'LoadCredential=proxy_username:/run/pgw/forwarders/%i/credentials/proxy_username'
assert_contains "${UNITS}/pgw-fwd@.service" 'LoadCredential=proxy_password:/run/pgw/forwarders/%i/credentials/proxy_password'
assert_contains "${UNITS}/pgw-ui.service" 'LoadCredential=ui_tls_cert:/etc/pgw/credentials-current/ui.crt'
assert_contains "${UNITS}/pgw-ui.service" 'LoadCredential=ui_tls_key:/etc/pgw/credentials-current/ui.key'
assert_contains "${UNITS}/pgw-ui.service" 'LoadCredential=ui_proxy_token:/etc/pgw/credentials-current/ui_proxy_token'
assert_contains "${UNITS}/pgw-ui.service" 'Environment=PGW_UI_WEB_DIR=/usr/local/share/pgw/web'
assert_contains "${UNITS}/pgw-ui.service" 'ExecStartPre=/usr/local/sbin/pgw-verify-ui-bind'
assert_not_contains "${UNITS}/pgw-api.service" '%d/'
assert_not_contains "${UNITS}/pgw-ui.service" '%d/'
assert_contains "${UNITS}/pgw-api.service" 'PGW_SECRETS_KEY_PATH=/run/credentials/pgw-api.service/secrets_key'
assert_contains "${UNITS}/pgw-ui.service" 'PGW_UI_TLS_CERT_FILE=/run/credentials/pgw-ui.service/ui_tls_cert'
assert_contains "${UNITS}/pgw-ui.service" 'PGW_UI_TLS_KEY_FILE=/run/credentials/pgw-ui.service/ui_tls_key'
for unit in pgw-agent.service pgw-fwd@.service pgw-ui.service pgw-health.service; do
    assert_not_contains "${UNITS}/${unit}" 'jwt_secret|admin_pass_hash|secrets_key'
done
for unit in pgw-api.service pgw-agent.service pgw-health.service; do
    assert_not_contains "${UNITS}/${unit}" 'ui_tls_cert|ui_tls_key'
done
for unit in pgw-fwd@.service pgw-ui.service pgw-health.service; do
    assert_not_contains "${UNITS}/${unit}" 'agent_service_token'
done
for unit in pgw-api.service pgw-agent.service pgw-ui.service pgw-health.service; do
    assert_not_contains "${UNITS}/${unit}" 'proxy_username|proxy_password'
done
for unit in pgw-agent.service pgw-fwd@.service pgw-health.service; do
    assert_not_contains "${UNITS}/${unit}" 'ui_proxy_token'
done

assert_contains "${ROOT}/deploy/sysusers.d/pgw.conf" 'm pgw-agent       pgw-fwd'
assert_contains "${ROOT}/deploy/tmpfiles.d/pgw.conf" 'd /var/lib/pgw/rules           0750 pgw-agent pgw-agent'
assert_contains "${ROOT}/deploy/tmpfiles.d/pgw.conf" 'd /run/pgw/forwarders          0750 pgw-agent pgw-fwd'
assert_contains "${ROOT}/deploy/tmpfiles.d/pgw.conf" 'd /etc/pgw/credential-generations 0700 root   root'
assert_contains "${ROOT}/deploy/tmpfiles.d/pgw.conf" 'z /etc/pgw/snapshot.hmac       0600 root      root'
assert_contains "${ROOT}/deploy/tmpfiles.d/pgw.conf" 'd /var/lib/pgw-lifecycle       0700 root      root'
assert_contains "${ROOT}/deploy/polkit-1/rules.d/50-pgw-agent-forwarder.rules" '^pgw-fwd@([0-9]+)\.service$'
assert_contains "${ROOT}/deploy/polkit-1/rules.d/50-pgw-agent-forwarder.rules" '["start", "stop", "restart"]'
assert_not_contains "${ROOT}/deploy/install-pgw.sh" 'setup_sudoers|^[[:space:]]*pgw .*NOPASSWD|git reset|git pull'
assert_not_contains "${ROOT}/deploy/update-pgw.sh" '^[[:space:]]*git (reset|pull|fetch)'
assert_not_contains "${ROOT}/update-pgw.sh" '^[[:space:]]*git (reset|pull|fetch|stash)|make build|systemctl (start|stop|restart)'
assert_not_contains "${ROOT}/update-pgw.sh" 'git -C|PGW_REVIEWED_COMMIT must be'
assert_contains "${ROOT}/deploy/install-pgw.sh" 'atomic_publish_directory'
assert_contains "${ROOT}/deploy/install-pgw.sh" '/usr/local/share/pgw/web'
assert_contains "${ROOT}/deploy/install-pgw.sh" 'install -d -o pgw-ui -g pgw-ui -m 0750 "${ui_stage}/static"'
assert_contains "${ROOT}/deploy/install-pgw.sh" 'chmod 0550 "${ui_stage}/static"'
"${PYTHON3}" -B - "${ROOT}/deploy/install-pgw.sh" <<'PY'
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
start = source.index("install_ui_assets() {")
end = source.index("\n}\n", start)
body = source[start:end]
markers = [
    'ui_stage="$(mktemp -d "${parent}/.web.new.XXXXXXXX")"',
    'install -d -o pgw-ui -g pgw-ui -m 0750 "${ui_stage}/static"',
    'chmod 0550 "${ui_stage}/static"',
    'chmod 0550 "${ui_stage}"',
    'chown pgw-ui:pgw-ui "${ui_stage}"',
    'atomic_publish_directory "${ui_stage}" "${UI_ROOT}"',
]
positions = [body.index(marker) for marker in markers]
if positions != sorted(positions) or any(body.count(marker) != 1 for marker in markers):
    raise SystemExit("unsafe UI stage construction/publication order")
PY
assert_contains "${ROOT}/deploy/install-pgw.sh" 'https://${ui_host}:8081/login'
assert_contains "${ROOT}/deploy/install-pgw.sh" 'quiesce_runtime'
assert_contains "${ROOT}/deploy/install-pgw.sh" 'enumerate_forwarder_units'
assert_contains "${ROOT}/deploy/install-pgw.sh" 'runtime-ruleset.nft'
assert_contains "${ROOT}/deploy/install-pgw.sh" 'net.ipv4.ip_forward=${saved_forward}'
assert_contains "${ROOT}/deploy/install-pgw.sh" 'verify_process_binary'
assert_contains "${ROOT}/deploy/install-pgw.sh" '/proc/${pid}/exe'
assert_contains "${ROOT}/deploy/install-pgw.sh" '/run/pgw-lifecycle.lock'
assert_contains "${ROOT}/deploy/install-pgw.sh" 'SAFE_PATH="/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"'
assert_contains "${ROOT}/deploy/update-pgw.sh" 'SAFE_PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"'
assert_contains "${ROOT}/update-pgw.sh" 'SAFE_PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"'
assert_contains "${ROOT}/deploy/install-pgw.sh" 'forbidden test environment:'
assert_not_contains "${ROOT}/deploy/install-pgw.sh" '"${PGW_INSTALL_TEST_COMMAND}" mutate'
assert_contains "${ROOT}/deploy/install-pgw.sh" 'trap - EXIT'
assert_contains "${ROOT}/deploy/install-pgw.sh" 'restore_rc=$?'
assert_not_contains "${ROOT}/deploy/install-pgw.sh" 'if ! restore_snapshot'
assert_contains "${ROOT}/deploy/update-pgw.sh" '/usr/local/sbin/pgw-release-launcher'
assert_contains "${ROOT}/deploy/install-pgw.sh" 'production root execution requires pgw-release-launcher'
assert_contains "${ROOT}/deploy/install-pgw.sh" '/proc/${PPID}/exe'
assert_contains "${ROOT}/deploy/install-pgw.sh" 'forged or invalid trusted launcher context'
assert_contains "${ROOT}/deploy/install-pgw.sh" 'PGW_RELEASE_FD_MAP'
assert_contains "${ROOT}/deploy/install-pgw.sh" 'snapshot_auth create'
assert_contains "${ROOT}/deploy/install-pgw.sh" 'deploy/restore_snapshot.py'
assert_contains "${ROOT}/deploy/install-pgw.sh" '"${PYTHON3}" -I'
assert_contains "${ROOT}/deploy/install-pgw.sh" 'snapshot_payload.py)" capture'
assert_not_contains "${ROOT}/deploy/install-pgw.sh" 'restore_snapshot\.py.*[[:space:]]capture[[:space:]]'
assert_not_contains "${ROOT}/deploy/install-pgw.sh" '"${backup_dir}/files/'
assert_contains "${ROOT}/deploy/install-pgw.sh" 'force_forwarding_off'
assert_not_contains "${ROOT}/deploy/install-pgw.sh" 'copy2|copytree|cp -a'
assert_contains "${ROOT}/deploy/restore_snapshot.py" 'os.fchown'
assert_contains "${ROOT}/deploy/restore_snapshot.py" 'renameat2'
assert_contains "${ROOT}/deploy/restore_snapshot.py" 'METADATA_VERSION = 3'
assert_contains "${ROOT}/deploy/restore_snapshot.py" 'resource_limit: nofile'
assert_contains "${ROOT}/deploy/restore_snapshot.py" 'max_aggregate_file_bytes'
assert_contains "${ROOT}/deploy/restore_snapshot.py" 'max_retained_fds'
assert_contains "${ROOT}/deploy/restore_snapshot.py" 'RecordMap'
assert_contains "${ROOT}/deploy/restore_snapshot.py" 'capture_all_posix'
assert_contains "${ROOT}/deploy/restore_snapshot.py" 'preflight_capture_node'
assert_contains "${ROOT}/deploy/restore_snapshot.py" 'snapshot source grew while copying file'
assert_contains "${ROOT}/deploy/restore_snapshot.py" 'O_NONBLOCK'
assert_contains "${ROOT}/deploy/install-pgw.sh" 'restore_capture_state_only'
assert_contains "${ROOT}/deploy/install-pgw.sh" 'elif ((full_snapshot_recovery))'
assert_contains "${ROOT}/deploy/install-pgw.sh" 'full_snapshot_recovery=1'
assert_contains "${ROOT}/deploy/install-pgw.sh" 'recovery_journal_auth verify'
assert_contains "${ROOT}/deploy/install-pgw.sh" 'authenticated-ciphertext verification is'
assert_contains "${ROOT}/deploy/install-pgw.sh" 'the publication gate'
assert_contains "${ROOT}/deploy/restore_snapshot.py" 'deterministic_restore_name'
assert_contains "${ROOT}/deploy/restore_snapshot.py" 'apply_open_directory_metadata(target_fd, item)'
assert_contains "${ROOT}/deploy/restore_snapshot.py" '_opened_node_matches'
assert_contains "${ROOT}/deploy/restore_snapshot.py" '_name_still_binds'
assert_contains "${ROOT}/deploy/restore_snapshot.py" '_stat_identity(current) != identity["stat"]'
assert_contains "${ROOT}/deploy/restore_snapshot.py" '_held_tree_still_binds'
assert_contains "${ROOT}/deploy/restore_snapshot.py" 'contextlib.ExitStack()'
assert_contains "${ROOT}/deploy/restore_snapshot.py" 'os.O_NOFOLLOW'
assert_contains "${ROOT}/deploy/restore_snapshot.py" 'exchanged restore tree failed authenticated metadata verification'
assert_not_contains "${ROOT}/deploy/restore_snapshot.py" 'token_hex|pgw-restore-absent\.'
assert_contains "${ROOT}/deploy/install-pgw.sh" 'write_recovery_journal'
assert_contains "${ROOT}/deploy/install-pgw.sh" 'secure_copy_root_file'
assert_not_contains "${ROOT}/deploy/install-pgw.sh" 'CGO_ENABLED=0.*build|PGW_GO_BINARY:-'
assert_contains "${ROOT}/deploy/launcher/secure_linux.go" 'os.Clearenv()'
assert_contains "${ROOT}/deploy/launcher/secure_linux.go" 'cmd.Dir = "/"'
assert_contains "${ROOT}/deploy/launcher/secure_linux.go" 'secureOpenRelative'
assert_not_contains "${ROOT}/deploy/launcher/secure_linux.go" 'Noctty|Setctty|Setsid|TIOCSCTTY|TIOCNOTTY'
assert_contains "${ROOT}/deploy/launcher/manifest.go" 'strings.HasPrefix(name, "PGW_")'
assert_contains "${ROOT}/deploy/tests/release_launcher_root_test.sh" '/usr/local/sbin/pgw-release-launcher --dry-run'
assert_contains "${ROOT}/deploy/tests/release_launcher_root_test.sh" 'mount --bind "${fixture}/etc" /etc'
assert_contains "${ROOT}/deploy/tests/release_launcher_root_test.sh" 'unsafe-ancestor.executed'
assert_contains "${ROOT}/deploy/tests/release_launcher_root_test.sh" 'chmod 0770 "${unsafe_ancestor}"'
assert_contains "${ROOT}/deploy/tests/release_launcher_root_test.sh" 'result=reject-126'
assert_contains "${ROOT}/deploy/tests/installer_transaction_test.sh" 'installer_harness.sh'
assert_contains "${ROOT}/deploy/tests/installer_transaction_test.sh" 'artifact_root="${temp_root}/release-artifacts"'
assert_not_contains "${ROOT}/deploy/tests/installer_transaction_test.sh" 'ROOT}/artifacts'
assert_contains "${ROOT}/deploy/tests/installer_transaction_test.sh" 'chgrp -hR "$(id -g)" "${system}" "${fixture}/runtime"'
assert_contains "${ROOT}/deploy/tests/installer_transaction_test.sh" 'non-root sealed UI encrypted materialization'
assert_contains "${ROOT}/deploy/tests/installer_transaction_test.sh" 'trap '\''cleanup_nonroot_sealed_ui_case "$?" "${fixture}"'\'' EXIT'
assert_contains "${ROOT}/deploy/tests/installer_transaction_test.sh" 'os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW'
assert_contains "${ROOT}/deploy/tests/installer_transaction_test.sh" 'injected post-materialize cleanup failure'
assert_contains "${ROOT}/deploy/tests/installer_transaction_test.sh" '"${EUID}:$(id -g):440"'
assert_not_contains "${ROOT}/deploy/tests/installer_harness.sh" 'production_restore_snapshot'
assert_contains "${ROOT}/deploy/tests/lifecycle_fake.sh" 'dispatch_restore_authority "$@"'
assert_contains "${ROOT}/deploy/tests/lifecycle_fake.sh" '"$7" == /usr/local/share/pgw/web'
assert_contains "${ROOT}/deploy/tests/lifecycle_fake.sh" '[[ -d "${target_arg}" && ! -L "${target_arg}" ]]'
assert_contains "${ROOT}/deploy/tests/lifecycle_fake.sh" 'unsafe fixture restore-authority UI file'
assert_not_contains "${ROOT}/deploy/install-pgw.sh" 'restore-authority'
assert_contains "${ROOT}/deploy/tests/installer_harness.sh" 'production_release_file'
assert_contains "${ROOT}/deploy/tests/installer_transaction_test.sh" "'phase=restoring'"
assert_contains "${ROOT}/deploy/tests/installer_transaction_test.sh" 'restore_crash:'
assert_contains "${ROOT}/deploy/tests/installer_transaction_test.sh" 'capture resource boundary: nofile/state-only recovery'
assert_contains "${ROOT}/deploy/tests/installer_transaction_test.sh" 'resource_limit: nofile'
assert_contains "${ROOT}/deploy/tests/installer_transaction_test.sh" 'capture lifecycle crash:'
assert_contains "${ROOT}/deploy/tests/installer_transaction_test.sh" 'full snapshot recovery failure remains fail-closed:'
assert_contains "${ROOT}/docs/deploy.md" 'originating, pinned release'
assert_contains "${ROOT}/deploy/tests/installer_transaction_test.sh" 'assert_restore_crash_phase'
assert_contains "${ROOT}/deploy/tests/restore_crash_driver.py" 'signal.SIGKILL'
assert_contains "${ROOT}/deploy/tests/restore_crash_driver.py" 'os.fsync(descriptor)'
assert_contains "${ROOT}/deploy/tests/restore_crash_driver.py" 'restore crash driver is unavailable to root'
assert_contains "${ROOT}/deploy/tests/lifecycle_fake.sh" 'python3 -I HELPER STATE SOURCE TARGET METADATA LOGICAL EXPECTED_UID'
assert_contains "${ROOT}/deploy/tests/lifecycle_fake.sh" '"${target_arg}" == "${root}/system${expected_logical}"'
assert_contains "${ROOT}/deploy/tests/lifecycle_fake.sh" '"${source_arg}" == "${snapshot_root}/files${expected_logical}"'
assert_contains "${ROOT}/deploy/tests/lifecycle_fake.sh" 'exec /usr/bin/python3 -I "${root}/restore-crash-driver.py" "${helper}" "${@:3}"'
assert_contains "${ROOT}/deploy/tests/nonroot_crash_evidence_runner.sh" 'chmod 0755 "${fixture}"'
assert_contains "${ROOT}/deploy/tests/nonroot_crash_evidence_runner.sh" 'PGW_REQUIRE_LINUX_RESTORE_CRASH=1'
assert_contains "${ROOT}/deploy/tests/nonroot_crash_evidence_runner.sh" 'setpriv --reuid="${evidence_uid}"'
assert_contains "${ROOT}/deploy/tests/nonroot_crash_evidence_runner.sh" '--no-new-privs --inh-caps=-all --ambient-caps=-all --bounding-set=-all'
assert_contains "${ROOT}/deploy/tests/nonroot_crash_evidence_runner.sh" 'for field in CapEff CapPrm CapInh CapAmb CapBnd'
assert_not_contains "${ROOT}/deploy/tests/nonroot_crash_evidence_runner.sh" 'SUDO_UID|passwd nobody'
assert_contains "${ROOT}/deploy/tests/restore_snapshot_test.sh" 'assert not module.node_matches'
assert_contains "${ROOT}/deploy/tests/restore_snapshot_test.sh" 'pause_after_child'
assert_contains "${ROOT}/deploy/tests/restore_snapshot_test.sh" 'fingerprint(stage_path) == prior_fingerprint'
assert_contains "${ROOT}/deploy/tests/restore_snapshot_test.sh" 'chmod 2750'
assert_contains "${ROOT}/deploy/tests/restore_snapshot_test.sh" 'chmod 1750'
assert_contains "${ROOT}/deploy/tests/base_installer_failclose_test.sh" "skip_or_fail 'unshare/mount command is missing'"
assert_contains "${ROOT}/deploy/tests/base_installer_failclose_test.sh" 'mount namespace creation denied (rc=${unshare_probe_rc}):'
assert_contains "${ROOT}/deploy/tests/base_installer_failclose_test.sh" 'unshare_probe_rc=$?'
assert_contains "${ROOT}/deploy/tests/base_installer_failclose_test.sh" 'if ((unshare_probe_rc != 0)); then'
assert_contains "${ROOT}/deploy/tests/base_installer_failclose_test.sh" '[[ "${required}" != 1 ]] || exit 77'
assert_contains "${ROOT}/.github/workflows/ci.yml" 'PGW_REQUIRE_NONROOT_CRASH_EVIDENCE=1'
assert_contains "${ROOT}/.github/workflows/ci.yml" 'PGW_REQUIRE_BASE_INSTALLER_EVIDENCE=1'
assert_contains "${ROOT}/.github/workflows/ci.yml" 'deploy/pgw-verify-base.sh /usr/local/sbin/pgw-verify-base'
assert_contains "${ROOT}/.github/workflows/ci.yml" 'deploy/pgw-verify-ui-bind.sh /usr/local/sbin/pgw-verify-ui-bind'
assert_contains "${ROOT}/deploy/tests/lifecycle_fake.sh" 'expected_logical'
assert_contains "${ROOT}/deploy/tests/lifecycle_fake.sh" '"${logical_arg}" == "${expected_logical}"'
assert_contains "${ROOT}/deploy/tests/installer_env_rejection_test.sh" '"${INSTALLER}" --dry-run'

if grep -RIEqs 'state\.json|PGW_STORE=(file|memory)|PGW_STORE_PATH|PGW_UI_AGENT|/agent/reconcile|PGW_DB_DSN|PGW_NATS_URL|User=pgw$|sudo systemctl (start|stop|restart) pgw-fwd' "${ROOT}/docs"; then
    fail 'tracked docs retain a prohibited legacy production architecture'
fi
for boundary in after_snapshot after_accounts after_binaries after_ui_assets after_credentials after_legacy_import after_units after_firewall after_services; do
    assert_contains "${ROOT}/deploy/install-pgw.sh" "${boundary}"
done

(cd -- "${ROOT}" && sha256sum -c deploy/ui-assets.sha256 >/dev/null) || fail 'UI source manifest mismatch'
manifest_fixture="$(mktemp -d)"
trap 'rm -rf -- "${manifest_fixture}"' EXIT
install -d "${manifest_fixture}/web/static" "${manifest_fixture}/deploy"
cp "${ROOT}/deploy/ui-assets.sha256" "${manifest_fixture}/deploy/ui-assets.sha256"
cp "${ROOT}"/web/static/{app.js,styles.css,login.js,layout.css} "${manifest_fixture}/web/static/"
printf '\nmanifest-tamper\n' >>"${manifest_fixture}/web/static/app.js"
if (cd -- "${manifest_fixture}" && sha256sum -c deploy/ui-assets.sha256 >/dev/null 2>&1); then
    fail 'tampered UI asset unexpectedly passed manifest validation'
fi

assert_contains "${ROOT}/deploy/nftables.conf" 'include "/etc/nftables.d/pgw-base.nft"'
assert_not_contains "${ROOT}/deploy/nftables.conf" 'pgw_dynamic'
assert_contains "${UNITS}/nftables.service.d/pgw.conf" 'ExecStartPost=/usr/local/sbin/pgw-verify-base'
assert_contains "${UNITS}/nftables.service.d/pgw.conf" 'ExecStartPre=/usr/sbin/nft -c -f /etc/nftables.conf'
assert_contains "${ROOT}/deploy/build-release.sh" 'deploy/systemd/nftables.service.d/pgw.conf'
assert_contains "${ROOT}/deploy/launcher/manifest.go" 'deploy/systemd/nftables.service.d/pgw.conf'
assert_contains "${UNITS}/systemd-sysctl.service.d/pgw.conf" 'Requires=nftables.service'
assert_contains "${UNITS}/systemd-sysctl.service.d/pgw.conf" 'After=nftables.service'
assert_contains "${ROOT}/deploy/sysctl-pgw.conf" 'net.ipv4.ip_forward = 1'
assert_contains "${ROOT}/pkg/nft/v2.go" 'management_input_drop_total'
assert_contains "${ROOT}/pkg/nft/v2.go" 'meta nfproto ipv6 tcp dport'
assert_contains "${ROOT}/deploy/pgw-verify-base.sh" 'exec /usr/local/bin/pgw-agent verify-boot-base'
assert_contains "${ROOT}/cmd/agent/nft_contract.go" '"-j", "list", "ruleset"'
assert_contains "${ROOT}/deploy/install-pgw-base.sh" 'net.ipv4.ip_forward=0'
assert_contains "${ROOT}/deploy/install-pgw-base.sh" 'restore_forwarding_final'
assert_contains "${ROOT}/deploy/install-pgw.sh" 'PGW_LAN_ADDRESS=${lan_address}'
assert_contains "${ROOT}/deploy/install-pgw.sh" 'PGW_UI_ADDR=${lan_address}:8081'
assert_not_contains "${ROOT}/deploy/install-pgw.sh" 'PGW_UI_ADDR=:8081'
assert_contains "${ROOT}/test/e2e/netns_legacy_web_only.sh" 'CONTROL same-LAN IPv6 reaches the management listener before rules'
assert_contains "${ROOT}/test/e2e/netns_legacy_web_only.sh" 'management_drop_after_wan6'
assert_contains "${ROOT}/test/e2e/netns_legacy_web_only.sh" 'mapped traffic used direct WAN after Forwarder failure'
assert_contains "${ROOT}/test/e2e/netns_legacy_web_only.sh" 'Forwarder-failure negative is ambiguous because the direct sentinel is unreachable'
assert_contains "${ROOT}/test/e2e/netns_legacy_web_only.sh" 'assert_management_ipv6_listener_live'
assert_contains "${ROOT}/test/e2e/netns_legacy_web_only.sh" 'pgw_assert_one_ipv6_management_drop'
assert_not_contains "${ROOT}/test/e2e/netns_legacy_web_only.sh" 'IPv6 service is unreachable|service is unreachable locally'
assert_contains "${ROOT}/test/e2e/ipv6_management_oracle_lib.sh" 'ss -Hlnpt6'
assert_contains "${ROOT}/test/e2e/ipv6_management_oracle_lib.sh" 'expected=$((before + 1))'
assert_contains "${ROOT}/docs/CI.md" '22.04 / systemd 249 unit compatibility'

"${ROOT}/deploy/install-pgw.sh" --dry-run

"${PYTHON3}" -I "${ROOT}/deploy/tests/polkit_rule_test.py" \
    "${ROOT}/deploy/polkit-1/rules.d/50-pgw-agent-forwarder.rules"
"${PYTHON3}" -I "${ROOT}/deploy/tests/evidence_contract_test.py" "${ROOT}"
"${PYTHON3}" -I "${ROOT}/deploy/tests/restore_resource_contract_test.py"
"${PYTHON3}" -I "${ROOT}/deploy/tests/snapshot_payload_contract_test.py"
"${PYTHON3}" -I "${ROOT}/deploy/tests/snapshot_payload_lifecycle_test.py"
node_candidate="${PGW_EVIDENCE_NODE:-$(command -v node || true)}"
[[ -n "${node_candidate}" ]] || fail 'Node is mandatory for actual polkit JavaScript evidence'
NODE_BINARY="$(readlink -f -- "${node_candidate}")"
readonly NODE_BINARY
[[ "${NODE_BINARY}" == /* && -x "${NODE_BINARY}" ]] || fail 'invalid Node evidence binary'
"${NODE_BINARY}" "${ROOT}/deploy/tests/polkit_rule_test.js" \
    "${ROOT}/deploy/polkit-1/rules.d/50-pgw-agent-forwarder.rules"
"${NODE_BINARY}" --check "${ROOT}/web/static/app.js"
"${NODE_BINARY}" --check "${ROOT}/web/static/login.js"
"${NODE_BINARY}" "${ROOT}/web/static/app.pagination.test.js"
bash "${ROOT}/deploy/tests/installer_transaction_test.sh"
bash "${ROOT}/deploy/tests/installer_env_rejection_test.sh"
bash "${ROOT}/deploy/tests/release_source_boundary_test.sh"
bash "${ROOT}/deploy/tests/release_provenance_test.sh"
bash "${ROOT}/deploy/tests/restore_snapshot_test.sh"
bash "${ROOT}/deploy/tests/snapshot_payload_linux_root_test.sh"
bash "${ROOT}/deploy/tests/base_installer_failclose_test.sh"

if [[ "${PGW_RUN_SYSTEMD_ANALYZE:-0}" == 1 ]]; then
    command -v systemd-analyze >/dev/null || fail 'systemd-analyze requested but unavailable'
    systemd-analyze verify \
        "${UNITS}/pgw-api.service" "${UNITS}/pgw-agent.service" \
        "${UNITS}/pgw-fwd@.service" "${UNITS}/pgw-ui.service" \
        "${UNITS}/pgw-health.service"
    for unit in pgw-api.service pgw-agent.service pgw-fwd@.service pgw-ui.service pgw-health.service; do
        systemd-analyze security --offline=yes "${UNITS}/${unit}" >/dev/null
    done
fi

printf 'deploy hardening tests: PASS\n'
