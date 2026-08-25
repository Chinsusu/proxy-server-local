#!/bin/bash
set -Eeuo pipefail

((EUID != 0)) || { printf 'native entrypoint test must run unprivileged\n' >&2; exit 96; }
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
[[ ! -e "${ROOT}/deploy/verify-release-attestation.sh" ]]

if [[ "$(uname -s)" != Linux ]]; then
    printf 'native AT_EXECFN runtime tests: SKIP (Linux required)\n'
    exit 0
fi
command -v cc >/dev/null || { printf 'native AT_EXECFN runtime tests: SKIP (cc unavailable)\n'; exit 0; }

fixture="$(mktemp -d)"
trap 'rm -rf -- "${fixture}"' EXIT
mkdir "${fixture}/installed"
cat >"${fixture}/native.c" <<'C'
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>

int main(int argc, char **argv) {
    (void)argv[0]; /* Caller controlled; deliberately not an authority input. */
    const char *expected = getenv("PGW_NATIVE_TEST_EXPECT_EXECFN");
    const char *execfn = (const char *)getauxval(AT_EXECFN);
    if (expected == NULL || execfn == NULL || strcmp(execfn, expected) != 0) return 69;
    if (argc != 3 || argv[1][0] != '/' || argv[2][0] != '/') return 2;
    const char *output_path = getenv("PGW_NATIVE_TEST_OUTPUT");
    const char *exit_text = getenv("PGW_NATIVE_TEST_EXIT");
    if (output_path == NULL || exit_text == NULL) return 70;
    FILE *input = fopen(output_path, "rb");
    if (input == NULL) return 70;
    unsigned char buffer[4096];
    size_t count;
    while ((count = fread(buffer, 1, sizeof(buffer), input)) != 0) {
        if (fwrite(buffer, 1, count, stdout) != count) { fclose(input); return 74; }
    }
    if (ferror(input) || fclose(input) != 0 || fflush(stdout) != 0) return 74;
    errno = 0;
    char *end = NULL;
    long code = strtol(exit_text, &end, 10);
    if (errno != 0 || end == exit_text || *end != '\0' || code < 0 || code > 255) return 70;
    return (int)code;
}
C
cat >"${fixture}/execveat-launcher.c" <<'C'
#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>

extern char **environ;

int main(int argc, char **argv) {
    if (argc != 5) return 2;
    int fd = open(argv[1], O_PATH | O_CLOEXEC);
    if (fd < 0) return 70;
    char *child_argv[] = {argv[2], argv[3], argv[4], 0};
    syscall(SYS_execveat, fd, "", child_argv, environ, AT_EMPTY_PATH);
    return 70;
}
C
cc -std=c11 -O2 -Wall -Wextra -Werror -o "${fixture}/installed/attestor" "${fixture}/native.c"
cc -std=c11 -O2 -Wall -Wextra -Werror -o "${fixture}/execveat-launcher" "${fixture}/execveat-launcher.c"
chmod 0555 "${fixture}/installed/attestor"
ln "${fixture}/installed/attestor" "${fixture}/installed/verify-release-attestation"

pair_valid() {
    local attestor="$1"
    local entrypoint="$2"
    [[ -f "${attestor}" && ! -L "${attestor}" && -x "${attestor}" ]] &&
    [[ -f "${entrypoint}" && ! -L "${entrypoint}" && -x "${entrypoint}" ]] &&
    [[ "$(stat -c '%d:%i' -- "${attestor}")" == "$(stat -c '%d:%i' -- "${entrypoint}")" ]] &&
    [[ "$(stat -c '%a:%h:%F' -- "${attestor}")" == '555:2:regular file' ]] &&
    [[ "$(stat -c '%a:%h:%F' -- "${entrypoint}")" == '555:2:regular file' ]]
}

attestor="${fixture}/installed/attestor"
entrypoint="${fixture}/installed/verify-release-attestation"
pair_valid "${attestor}" "${entrypoint}"

printf 'touch %q\n' "${fixture}/bash-env-executed" >"${fixture}/hostile-bash-env"
printf 'candidate\n' >"${fixture}/candidate.tar"
printf 'bundle\n' >"${fixture}/bundle.jsonl"
printf '{}' >"${fixture}/empty-output.json"
hex_a="$(printf 'a%.0s' {1..64})"
hex_b="$(printf 'b%.0s' {1..64})"
hex_c="$(printf 'c%.0s' {1..64})"
hex_d="$(printf 'd%.0s' {1..64})"

expect_path_rejection() {
    local label="$1"
    shift
    set +e
    BASH_ENV="${fixture}/hostile-bash-env" \
      PGW_NATIVE_TEST_EXPECT_EXECFN="${entrypoint}" \
      PGW_NATIVE_TEST_OUTPUT="${fixture}/empty-output.json" PGW_NATIVE_TEST_EXIT=0 \
      "$@" >"${fixture}/${label}.stdout" 2>"${fixture}/${label}.stderr"
    local rc=$?
    set -e
    [[ "${rc}" == 69 && ! -s "${fixture}/${label}.stdout" && ! -e "${fixture}/bash-env-executed" ]] || {
        printf 'native execution path was not rejected: %s (rc=%s)\n' "${label}" "${rc}" >&2
        exit 1
    }
}

expect_path_rejection direct-attestor "${attestor}" "${fixture}/candidate.tar" "${fixture}/bundle.jsonl"
expect_path_rejection exec-a-spoof env -u BASH_ENV /bin/bash --noprofile --norc -c \
  'exec -a "$1" "$2" "$3" "$4"' _ "${entrypoint}" "${attestor}" \
  "${fixture}/candidate.tar" "${fixture}/bundle.jsonl"
(
    cd "${fixture}/installed"
    expect_path_rejection relative-wrapper ./verify-release-attestation \
      "${fixture}/candidate.tar" "${fixture}/bundle.jsonl"
)
ln -s "${entrypoint}" "${fixture}/wrapper-symlink"
expect_path_rejection symlink-wrapper "${fixture}/wrapper-symlink" \
  "${fixture}/candidate.tar" "${fixture}/bundle.jsonl"
expect_path_rejection proc-fd env -u BASH_ENV /bin/bash --noprofile --norc -c \
  'exec {fd}<"$1"; exec -a "$2" "/proc/self/fd/${fd}" "$3" "$4"' _ \
  "${entrypoint}" "${entrypoint}" "${fixture}/candidate.tar" "${fixture}/bundle.jsonl"
expect_path_rejection execveat-fd "${fixture}/execveat-launcher" \
  "${entrypoint}" "${entrypoint}" "${fixture}/candidate.tar" "${fixture}/bundle.jsonl"

for outcome in \
    '0 promoted' \
    '75 pre_commit_failed' \
    '76 commit_indeterminate' \
    '77 committed_durability_indeterminate'; do
    read -r expected_rc status <<<"${outcome}"
    printf '%s' \
        "{\"schema\":\"pgw-promotion-result-v1\",\"status\":\"${status}\",\"release_id\":\"v1.2.3\",\"release_manifest_sha256\":\"${hex_a}\",\"candidate_sha256\":\"${hex_b}\",\"bundle_sha256\":\"${hex_c}\",\"predicate_sha256\":\"${hex_d}\"}" \
        >"${fixture}/expected.json"
    set +e
    BASH_ENV="${fixture}/hostile-bash-env" \
      PGW_NATIVE_TEST_EXPECT_EXECFN="${entrypoint}" \
      PGW_NATIVE_TEST_OUTPUT="${fixture}/expected.json" PGW_NATIVE_TEST_EXIT="${expected_rc}" \
      "${entrypoint}" "${fixture}/candidate.tar" "${fixture}/bundle.jsonl" \
      >"${fixture}/actual.json" 2>"${fixture}/actual.stderr"
    actual_rc=$?
    set -e
    [[ "${actual_rc}" == "${expected_rc}" ]]
    cmp --silent "${fixture}/expected.json" "${fixture}/actual.json"
    [[ ! -s "${fixture}/actual.stderr" && ! -e "${fixture}/bash-env-executed" ]]
done

# Updating attestor first creates only a fail-closed mismatch window; installing
# the staged entrypoint second restores one exact two-link pair.
cp -- "${attestor}" "${fixture}/installed/.attestor.next"
chmod 0555 "${fixture}/installed/.attestor.next"
ln "${fixture}/installed/.attestor.next" "${fixture}/installed/.verify.next"
pair_valid "${fixture}/installed/.attestor.next" "${fixture}/installed/.verify.next"
mv -f "${fixture}/installed/.attestor.next" "${attestor}"
if pair_valid "${attestor}" "${entrypoint}"; then
    printf 'transient native pair mismatch did not fail closed\n' >&2
    exit 1
fi
mv -f "${fixture}/installed/.verify.next" "${entrypoint}"
pair_valid "${attestor}" "${entrypoint}"

cp -- "${attestor}" "${fixture}/wrong-copy"
chmod 0555 "${fixture}/wrong-copy"
if pair_valid "${attestor}" "${fixture}/wrong-copy"; then
    printf 'copied entrypoint accepted\n' >&2
    exit 1
fi
cp -- "${attestor}" "${fixture}/other-inode"
chmod 0555 "${fixture}/other-inode"
ln "${fixture}/other-inode" "${fixture}/wrong-hardlink"
if pair_valid "${attestor}" "${fixture}/wrong-hardlink"; then
    printf 'hardlink to a different inode accepted\n' >&2
    exit 1
fi
ln "${attestor}" "${fixture}/unexpected-third-link"
if pair_valid "${attestor}" "${entrypoint}"; then
    printf 'entrypoint with unexpected third link accepted\n' >&2
    exit 1
fi

printf 'native AT_EXECFN, hardlink, BASH_ENV and stdout/exit tests: PASS\n'
