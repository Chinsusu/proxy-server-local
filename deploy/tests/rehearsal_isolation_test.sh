#!/usr/bin/env bash
set -Eeuo pipefail

(($# == 1)) || { printf 'usage: rehearsal_isolation_test.sh ASSEMBLY\n' >&2; exit 2; }
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
HELPER="${ROOT}/deploy/tests/release_snapshot.py"
ASSEMBLY="$(readlink -f -- "$1")"
TEMP_ROOT="$(mktemp -d)"
trap 'rm -rf -- "${TEMP_ROOT}"' EXIT

python3 -I "${HELPER}" snapshot "${ASSEMBLY}" "${TEMP_ROOT}/valid"
python3 -I "${HELPER}" verify "${TEMP_ROOT}/valid" >/dev/null

repin() {
    local root="$1" digest
    digest="$(sha256sum "${root}/release/release.manifest" | awk '{print $1}')"
    sed -i "s/^manifest_sha256 .*/manifest_sha256 ${digest}/" \
        "${root}/release-trust.manifest"
}

must_reject_verify() {
    local name="$1"
    if python3 -I "${HELPER}" verify "${TEMP_ROOT}/${name}" \
        >"${TEMP_ROOT}/${name}.stdout" 2>"${TEMP_ROOT}/${name}.stderr"; then
        printf 'strict verifier accepted invalid case: %s\n' "${name}" >&2
        exit 1
    fi
}

cp -a "${TEMP_ROOT}/valid" "${TEMP_ROOT}/duplicate"
grep '^file ' "${TEMP_ROOT}/duplicate/release/release.manifest" | head -n1 \
    >>"${TEMP_ROOT}/duplicate/release/release.manifest"
repin "${TEMP_ROOT}/duplicate"
must_reject_verify duplicate

cp -a "${TEMP_ROOT}/valid" "${TEMP_ROOT}/missing"
sed -i '\# deploy/tests/installer_harness[.]sh$#d' \
    "${TEMP_ROOT}/missing/release/release.manifest"
rm -f "${TEMP_ROOT}/missing/release/deploy/tests/installer_harness.sh"
repin "${TEMP_ROOT}/missing"
must_reject_verify missing

cp -a "${TEMP_ROOT}/valid" "${TEMP_ROOT}/extra"
printf 'unexpected\n' >"${TEMP_ROOT}/extra/release/unexpected"
extra_digest="$(sha256sum "${TEMP_ROOT}/extra/release/unexpected" | awk '{print $1}')"
printf 'file %s 0644 unexpected\n' "${extra_digest}" \
    >>"${TEMP_ROOT}/extra/release/release.manifest"
repin "${TEMP_ROOT}/extra"
must_reject_verify extra

for name in absolute traversal; do
    cp -a "${TEMP_ROOT}/valid" "${TEMP_ROOT}/${name}"
done
sed -i '2s# deploy/install-pgw[.]sh$# /etc/passwd#' \
    "${TEMP_ROOT}/absolute/release/release.manifest"
repin "${TEMP_ROOT}/absolute"
must_reject_verify absolute
sed -i '2s# deploy/install-pgw[.]sh$# deploy/../install-pgw.sh#' \
    "${TEMP_ROOT}/traversal/release/release.manifest"
repin "${TEMP_ROOT}/traversal"
must_reject_verify traversal

cp -a "${TEMP_ROOT}/valid" "${TEMP_ROOT}/symlink-source"
ln -s /etc/passwd "${TEMP_ROOT}/symlink-source/host-passwd"
if python3 -I "${HELPER}" snapshot "${TEMP_ROOT}/symlink-source" \
    "${TEMP_ROOT}/symlink-output" >/dev/null 2>&1; then
    printf 'snapshot accepted symlink input\n' >&2
    exit 1
fi

cp -a "${TEMP_ROOT}/valid" "${TEMP_ROOT}/fifo-source"
mkfifo "${TEMP_ROOT}/fifo-source/special.fifo"
if python3 -I "${HELPER}" snapshot "${TEMP_ROOT}/fifo-source" \
    "${TEMP_ROOT}/fifo-output" >/dev/null 2>&1; then
    printf 'snapshot accepted FIFO input\n' >&2
    exit 1
fi

cp -a "${TEMP_ROOT}/valid" "${TEMP_ROOT}/swap-source"
dd if=/dev/zero of="${TEMP_ROOT}/swap-source/race.bin" bs=1M count=128 status=none
(
    while :; do
        printf x | dd of="${TEMP_ROOT}/swap-source/race.bin" bs=1 seek=67108864 \
            conv=notrunc status=none || exit
        printf y | dd of="${TEMP_ROOT}/swap-source/race.bin" bs=1 seek=67108864 \
            conv=notrunc status=none || exit
    done
) &
writer_pid=$!
set +e
python3 -I "${HELPER}" snapshot "${TEMP_ROOT}/swap-source" \
    "${TEMP_ROOT}/swap-output" >/dev/null 2>&1
swap_rc=$?
kill "${writer_pid}" >/dev/null 2>&1 || true
wait "${writer_pid}" 2>/dev/null || true
set -e
((swap_rc != 0)) || {
    printf 'snapshot accepted concurrently mutated source\n' >&2
    exit 1
}

printf 'rehearsal snapshot/parser isolation tests: PASS\n'
