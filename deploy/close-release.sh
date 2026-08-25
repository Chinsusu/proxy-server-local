#!/bin/bash
set -Eeuo pipefail

((EUID != 0)) || { printf 'release closure must run unprivileged\n' >&2; exit 96; }
(($# == 2)) || { printf 'usage: close-release.sh CANDIDATE_DIRECTORY OUTPUT_TAR\n' >&2; exit 2; }
for tool in cmp date dirname find mktemp mv python3 rm sha256sum tar; do
    command -v "${tool}" >/dev/null 2>&1 || { printf 'missing release closure tool: %s\n' "${tool}" >&2; exit 69; }
done
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
candidate="$1"
output="$2"
[[ -d "${candidate}" && ! -L "${candidate}" ]] || { printf 'candidate must be a real directory\n' >&2; exit 2; }
[[ "${output}" == /* && "${output}" == *.tar && ! -e "${output}" ]] || {
    printf 'output must be a new absolute .tar path\n' >&2; exit 2;
}
parent="$(dirname -- "${output}")"
[[ -d "${parent}" ]] || { printf 'tar parent does not exist\n' >&2; exit 2; }
work="$(mktemp -d "${parent}/.pgw-close.XXXXXXXX")"
trap 'rm -rf -- "${work}"' EXIT
/usr/bin/python3 -I "${root}/deploy/snapshot_release_tree.py" snapshot \
    "${candidate}" "${work}/candidate" "${work}/candidate.snapshot.manifest"
/usr/bin/python3 -I "${root}/deploy/snapshot_release_tree.py" verify \
    "${work}/candidate" "${work}/candidate.snapshot.manifest"
(
    cd -- "${work}/candidate"
    sha256sum -c SHA256SUMS >/dev/null
)
source_time="$(awk '$1=="source_commit_time" {print $2}' "${work}/candidate/assembly/version.manifest")"
epoch="$(date -u -d "${source_time}" +%s)"
[[ "${epoch}" =~ ^[0-9]+$ ]] || { printf 'invalid source epoch\n' >&2; exit 65; }
for pass in a b; do
    tar --sort=name --format=posix --pax-option=delete=atime,delete=ctime \
        --mtime="@${epoch}" --clamp-mtime --owner=0 --group=0 --numeric-owner \
        -C "${work}/candidate" -cf "${work}/candidate-${pass}.tar" .
done
cmp -s "${work}/candidate-a.tar" "${work}/candidate-b.tar" || {
    printf 'closed candidate tar is not deterministic\n' >&2
    exit 65
}
mv -T -- "${work}/candidate-a.tar" "${output}"
printf 'closed candidate tar: %s\n' "${output}"
printf 'sha256:%s\n' "$(sha256sum "${output}" | awk '{print $1}')"
