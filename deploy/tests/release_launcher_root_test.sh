#!/bin/bash
set -Eeuo pipefail

if [[ "$(uname -s)" != Linux ]]; then
    printf 'production root launcher evidence requires Linux disposable isolation\n' >&2
    exit 77
fi
if ((EUID != 0)); then
    printf 'production root launcher evidence: NOT_RUN outside authenticated isolated root runner\n' >&2
    exit 77
fi
(($# == 2)) || {
    printf 'usage: release_launcher_root_test.sh ASSEMBLED_RELEASE DISPOSABLE_BOUNDARY_ASSERTION\n' >&2
    exit 2
}
[[ "${PGW_DISPOSABLE_FULL_SYSTEM:-}" == pgw-disposable-vm-v1 ]] || {
    printf 'root launcher test refuses an unauthenticated/shared runner\n' >&2
    exit 96
}
boundary_assertion="$2"
[[ "${boundary_assertion}" == /* && -f "${boundary_assertion}" && ! -L "${boundary_assertion}" &&
   "$(stat -c '%U:%G:%a' "${boundary_assertion}")" == root:root:600 ]] || {
    printf 'invalid disposable boundary assertion\n' >&2
    exit 96
}
expected_boundary=$'format pgw-disposable-boundary-v1\nprovider vm-or-dedicated-rootfs\nsource authenticated-bundle\ncredential_free true\nprivate_namespaces user,pid,mount,network,ipc,uts'
[[ "$(<"${boundary_assertion}")" == "${expected_boundary}" ]] || {
    printf 'disposable boundary assertion is incomplete\n' >&2
    exit 96
}
while IFS='=' read -r env_name _; do
    [[ "${env_name}" =~ (TOKEN|SECRET|PASSWORD|PRIVATE_KEY|CREDENTIAL) ]] || continue
    [[ "${env_name}" == PGW_DISPOSABLE_FULL_SYSTEM ]] || {
        printf 'credential-bearing environment is forbidden in root rehearsal: %s\n' "${env_name}" >&2
        exit 96
    }
done < <(env)
command -v unshare >/dev/null && command -v mount >/dev/null || {
    printf 'full namespace isolation tools unavailable\n' >&2
    exit 77
}

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
snapshot_helper="${script_dir}/release_snapshot.py"
python3_resolved="$(readlink -f -- /usr/bin/python3 2>/dev/null || true)"
[[ -f "${snapshot_helper}" && ! -L "${snapshot_helper}" &&
   "${python3_resolved}" =~ ^/usr/bin/python3([.][0-9]+)*$ && -f "${python3_resolved}" ]] || {
    printf 'trusted snapshot helper or fixed Python is unavailable\n' >&2
    exit 77
}
snapshot_work="$(mktemp -d /tmp/pgw-root-release-snapshot.XXXXXXXX)"
fixture=''
cleanup() {
    [[ -z "${fixture}" || "${fixture}" == /tmp/pgw-root-launcher-test.* ]] && rm -rf -- "${fixture:-${snapshot_work}/none}"
    [[ "${snapshot_work}" == /tmp/pgw-root-release-snapshot.* ]] && rm -rf -- "${snapshot_work}"
}
trap cleanup EXIT
/usr/bin/python3 -I "${snapshot_helper}" snapshot "$1" "${snapshot_work}/assembly"
/usr/bin/python3 -I "${snapshot_work}/assembly/release/deploy/tests/release_snapshot.py" \
    verify "${snapshot_work}/assembly" >"${snapshot_work}/verification.tsv"
assembly="${snapshot_work}/assembly"
[[ -d "${assembly}/release" && -f "${assembly}/release-trust.manifest" &&
   -x "${assembly}/pgw-release-launcher" ]] || {
    printf 'invalid unprivileged release assembly\n' >&2
    exit 1
}
release_id="$(awk '$1=="release_id" {print $2}' "${assembly}/release-trust.manifest")"
[[ "${release_id}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]

# Keep the harness outside every mountpoint overlaid below.  A fixture under
# /var would disappear from its own namespace as soon as /var is bind-mounted.
# /run is commonly noexec on hardened hosts, so it cannot hold the launcher
# whose execution this oracle must prove.
fixture="$(mktemp -d /tmp/pgw-root-launcher-test.XXXXXXXX)"
chmod 0700 "${fixture}"
install -d -m 0755 \
    "${fixture}/etc/pgw" \
    "${fixture}/opt/pgw/releases/${release_id}" \
    "${fixture}/usr/local/sbin" \
    "${fixture}/attacker"
# `/usr/bin/awk` is an /etc/alternatives symlink on Debian/Ubuntu.  The
# isolated /etc bind must retain those distro command links or the oracle tests
# a broken synthetic userspace instead of the launcher.
if [[ -d /etc/alternatives ]]; then
    install -d -m 0755 "${fixture}/etc/alternatives"
    cp -a -- /etc/alternatives/. "${fixture}/etc/alternatives/"
fi
cp -a -- "${assembly}/release/." "${fixture}/opt/pgw/releases/${release_id}/"
install -o root -g root -m 0600 "${assembly}/release-trust.manifest" \
    "${fixture}/etc/pgw/release-trust.manifest"
install -o root -g root -m 0755 "${assembly}/pgw-release-launcher" \
    "${fixture}/usr/local/sbin/pgw-release-launcher"
chown -R root:root "${fixture}/etc" "${fixture}/var" "${fixture}/usr"
find "${fixture}/etc" "${fixture}/var" "${fixture}/usr" -type d -exec chmod go-w {} +

sentinel="${fixture}/hostile-cwd-imported"
cat >"${fixture}/attacker/pgw_cwd_probe.py" <<PY
from pathlib import Path
Path(${sentinel@Q}).write_text("hostile cwd imported")
PY

set +e
unshare --user --map-root-user --pid --mount --net --ipc --uts --fork --mount-proc \
    /bin/bash -c '
    set -Eeuo pipefail
    fixture="$1"
    mount --make-rprivate /
    mount --bind "${fixture}/etc" /etc
    mount --bind "${fixture}/var" /var
    mount --bind "${fixture}/opt" /opt
    mount --bind "${fixture}/usr/local/sbin" /usr/local/sbin
    cd -- "${fixture}/attacker"
    env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
        LANG=C LC_ALL=C /usr/local/sbin/pgw-release-launcher --dry-run
' _ "${fixture}" >"${fixture}/launcher.stdout" 2>"${fixture}/launcher.stderr"
launcher_rc=$?
set -e
if ((launcher_rc != 0)); then
    printf 'isolated launcher dry-run failed rc=%s\n' "${launcher_rc}" >&2
    sed -n '1,160p' "${fixture}/launcher.stderr" >&2
    exit "${launcher_rc}"
fi

grep -Fq 'dry-run PASS' "${fixture}/launcher.stderr"
[[ ! -e "${sentinel}" ]]

# The same production launcher must reject a root-owned but group-writable
# ancestor.  This is executed under root rather than inferred from a skipped Go
# unit test, and the exact marker proves the negative case reached the launcher.
unsafe_ancestor="${fixture}/opt/pgw/releases"
chmod 0770 "${unsafe_ancestor}"
[[ "$(stat -c '%a' -- "${unsafe_ancestor}")" == 770 ]]
unsafe_marker="${fixture}/unsafe-ancestor.executed"
[[ ! -e "${unsafe_marker}" ]]
set +e
unshare --user --map-root-user --pid --mount --net --ipc --uts --fork --mount-proc \
    /bin/bash -c '
    set -Eeuo pipefail
    fixture="$1"; marker="$2"
    mount --make-rprivate /
    mount --bind "${fixture}/etc" /etc
    mount --bind "${fixture}/var" /var
    mount --bind "${fixture}/opt" /opt
    mount --bind "${fixture}/usr/local/sbin" /usr/local/sbin
    printf "case=group-writable-ancestor\nphase=entered\n" >"${marker}"
    set +e
    env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
        LANG=C LC_ALL=C /usr/local/sbin/pgw-release-launcher --dry-run
    rc=$?
    set -e
    [[ "${rc}" == 126 ]]
    printf "result=reject-126\n" >>"${marker}"
' _ "${fixture}" "${unsafe_marker}" \
    >"${fixture}/unsafe-ancestor.stdout" 2>"${fixture}/unsafe-ancestor.stderr"
unsafe_rc=$?
set -e
if ((unsafe_rc != 0)); then
    printf 'isolated unsafe-ancestor oracle failed rc=%s\n' "${unsafe_rc}" >&2
    sed -n '1,160p' "${fixture}/unsafe-ancestor.stderr" >&2
    exit "${unsafe_rc}"
fi
expected_marker=$'case=group-writable-ancestor\nphase=entered\nresult=reject-126'
[[ "$(<"${unsafe_marker}")" == "${expected_marker}" ]]
grep -Fq 'owner/mode violates root trust boundary' "${fixture}/unsafe-ancestor.stderr"
printf 'production pinned root launcher evidence: PASS\n'
