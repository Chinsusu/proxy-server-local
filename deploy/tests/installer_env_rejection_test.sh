#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
INSTALLER="${ROOT}/deploy/install-pgw.sh"
UPDATE_WRAPPER="${ROOT}/deploy/update-pgw.sh"
COMPAT_WRAPPER="${ROOT}/update-pgw.sh"
HARNESS="${ROOT}/deploy/tests/installer_harness.sh"
BASH_BINARY="$(command -v bash)"
readonly TEST_VARS=(
    PGW_INSTALL_TEST_MODE PGW_INSTALL_TEST_ROOT PGW_INSTALL_TEST_COMMAND
    PGW_INSTALL_SYSTEM_ROOT PGW_INSTALL_BACKUP_ROOT PGW_RESTORE_FAIL_AT
    PGW_FAIL_AT PGW_FAKE_ROOT PGW_INSTALL_INTERNAL_SOURCE PGW_INTERNAL_TEST_MARKER
    PGW_INTERNAL_PYTHON_BINARY
)
readonly PRODUCTION_OVERRIDES=(
    PGW_SOURCE_DIR PGW_GO_BINARY PGW_REVIEWED_CHECKOUT PGW_REVIEWED_COMMIT
    PGW_ADMIN_PASS_FILE PGW_UI_TLS_CERT_SOURCE PGW_UI_TLS_KEY_SOURCE PGW_UI_PROXY_TOKEN_SOURCE
)

fixture="$(mktemp -d)"
trap 'rm -rf -- "${fixture}"' EXIT
mkdir -p "${fixture}/hostile"
sentinel="${fixture}/hostile-command-ran"
for command_name in env bash dirname sha256sum systemctl nft git readlink; do
    printf '#!/bin/bash\nprintf "hostile:%s\\n" >>%q\n' "${command_name}" "${sentinel}" \
        >"${fixture}/hostile/${command_name}"
    chmod 0700 "${fixture}/hostile/${command_name}" 2>/dev/null || true
done

for variable in "${PRODUCTION_OVERRIDES[@]}"; do
    set +e
    env "${variable}=forbidden" PATH="${fixture}/hostile" "${BASH_BINARY}" "${INSTALLER}" --dry-run \
        >"${fixture}/${variable}.out" 2>"${fixture}/${variable}.err"
    rc=$?
    set -e
    [[ "${rc}" == 64 ]]
    grep -Fq "forbidden production override: ${variable}" "${fixture}/${variable}.err"
    [[ ! -e "${sentinel}" ]]
done
printf '#!/bin/bash\nprintf "test-command\\n" >>%q\n' "${sentinel}" >"${fixture}/test-command"
chmod 0700 "${fixture}/test-command" 2>/dev/null || true

# Prove the hostile commands and payload are live sentinels rather than inert
# fixtures. Direct paths exercise their absolute interpreter independently of
# the hostile PATH used by the production entrypoint checks below.
for command_name in env bash dirname sha256sum systemctl nft git readlink; do
    "${fixture}/hostile/${command_name}"
    grep -Fxq "hostile:${command_name}" "${sentinel}"
done
"${fixture}/test-command"
grep -Fxq 'test-command' "${sentinel}"
[[ "$(wc -l <"${sentinel}")" == 9 ]]
rm -f -- "${sentinel}"

for variable in "${TEST_VARS[@]}"; do
    value=forbidden
    [[ "${variable}" != PGW_INSTALL_TEST_COMMAND ]] || value="${fixture}/test-command"
    set +e
    env "${variable}=${value}" PATH="${fixture}/hostile" "${BASH_BINARY}" "${INSTALLER}" --dry-run \
        >"${fixture}/${variable}.out" 2>"${fixture}/${variable}.err"
    rc=$?
    set -e
    [[ "${rc}" == 64 ]]
    grep -Fq "forbidden test environment: ${variable}" "${fixture}/${variable}.err"
    [[ ! -e "${sentinel}" ]]
done

# The launcher marker and FD map are not an authentication mechanism by
# themselves. A direct Bash invocation must also prove its parent executable is
# the fixed, root-owned launcher.
set +e
env PGW_TRUSTED_LAUNCH=pgw-release-launcher-v1 PGW_RELEASE_ID=forged \
    PGW_RELEASE_FD_MAP='deploy/install-pgw.sh=3' \
    "${BASH_BINARY}" "${INSTALLER}" --dry-run \
    >"${fixture}/forged-launch.out" 2>"${fixture}/forged-launch.err"
forged_launch_rc=$?
set -e
[[ "${forged_launch_rc}" == 126 ]]
grep -Fq 'forged or invalid trusted launcher context' "${fixture}/forged-launch.err"
[[ ! -e "${sentinel}" ]]

# A hostile inherited PATH is replaced before even dirname resolves SCRIPT_DIR.
PATH="${fixture}/hostile" "${BASH_BINARY}" "${INSTALLER}" --dry-run \
    >"${fixture}/safe-path.out" 2>"${fixture}/safe-path.err"
grep -Fq 'dry-run PASS' "${fixture}/safe-path.err"
[[ ! -e "${sentinel}" ]]

# Direct execution proves the kernel uses /bin/bash and each entrypoint resets
# PATH before dirname, git, readlink or any other external command.
PATH="${fixture}/hostile" "${INSTALLER}" --dry-run \
    >"${fixture}/direct-install.out" 2>"${fixture}/direct-install.err"
[[ "$?" == 0 ]]
grep -Fq 'dry-run PASS' "${fixture}/direct-install.err"

set +e
PATH="${fixture}/hostile" "${UPDATE_WRAPPER}" invalid \
    >"${fixture}/direct.deploy-update.out" 2>"${fixture}/direct.deploy-update.err"
update_rc=$?
PATH="${fixture}/hostile" "${COMPAT_WRAPPER}" invalid \
    >"${fixture}/direct.compat-update.out" 2>"${fixture}/direct.compat-update.err"
compat_rc=$?
PATH="${fixture}/hostile" "${HARNESS}" \
    >"${fixture}/direct.harness.out" 2>"${fixture}/direct.harness.err"
harness_rc=$?
set -e

[[ "${update_rc}" == 126 ]]
[[ "${compat_rc}" == 126 ]]
if ((EUID == 0)); then
    grep -Fq '[pgw-update] ERROR: root script entrypoint disabled' "${fixture}/direct.deploy-update.err"
    grep -Fq '[pgw-update-compat] ERROR: root script entrypoint disabled' \
        "${fixture}/direct.compat-update.err"
    [[ "${harness_rc}" == 96 ]]
    grep -Fq 'installer harness must run non-root' "${fixture}/direct.harness.err"
else
    grep -Fq '[pgw-update] ERROR: production lifecycle requires' "${fixture}/direct.deploy-update.err"
    grep -Fq '[pgw-update-compat] ERROR: retired' "${fixture}/direct.compat-update.err"
    [[ "${harness_rc}" == 2 ]]
    grep -Fq 'usage: installer_harness.sh FIXTURE BOUNDARY RESTORE_FAILURE' \
        "${fixture}/direct.harness.err"
fi
[[ ! -e "${sentinel}" ]]

if command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
    set +e
    sudo -n env PATH="${fixture}/hostile" "${HARNESS}" \
        >"${fixture}/root-harness.out" 2>"${fixture}/root-harness.err"
    rc=$?
    set -e
    [[ "${rc}" == 96 ]]
    grep -Eq 'installer harness must run non-root|cannot be sourced as root' "${fixture}/root-harness.err"
    [[ ! -e "${sentinel}" ]]
else
    grep -Fq '((EUID != 0))' "${HARNESS}"
fi

printf 'installer production env/PATH rejection tests: PASS\n'
