#!/bin/bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
if ((EUID == 0)); then
    set +e
    /bin/bash "${ROOT}/deploy/build-release.sh" test /tmp/pgw-forbidden-root-release >/dev/null 2>&1
    rc=$?
    set -e
    [[ "${rc}" == 96 ]]
    printf 'release provenance root rejection: PASS\n'
    exit 0
fi
case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*)
        printf 'release provenance tests: SKIP (Linux ELF inspection required)\n'
        exit 0
        ;;
esac

fixture="$(mktemp -d)"
trap 'rm -rf -- "${fixture}"' EXIT
output="${fixture}/assembled"
build_args=()
if [[ -n "$(git -C "${ROOT}" status --porcelain=v1 --untracked-files=all)" ]]; then
    build_args+=(--rehearsal-dirty)
fi

# Forged GitHub variables are ambient strings only: they must never make local
# metadata promotable or appear in the candidate identity.
set +e
GITHUB_RUN_ID=999 GITHUB_RUN_ATTEMPT=7 GITHUB_SHA=0000000000000000000000000000000000000000 \
GITHUB_REF_TYPE=tag GITHUB_REF_NAME=v99.99.99 \
    /bin/bash "${ROOT}/deploy/build-release.sh" "${build_args[@]}" test-release-v2 "${output}" >"${fixture}/build.out" 2>"${fixture}/build.err"
build_rc=$?
set -e
if ((build_rc != 0)); then
    printf 'DEBUG build-release.sh rc=%s build_args=%s\n' "${build_rc}" "${build_args[*]:-}" >&2
    printf 'DEBUG build.out:\n' >&2; cat "${fixture}/build.out" >&2
    printf 'DEBUG build.err:\n' >&2; cat "${fixture}/build.err" >&2
    exit "${build_rc}"
fi
printf 'DEBUG checkpoint: build-release.sh call itself succeeded\n' >&2
grep -Fxq 'format pgw-version-v2' "${output}/version.manifest"; printf 'DEBUG a1\n' >&2
grep -Fxq 'candidate_only true' "${output}/version.manifest"; printf 'DEBUG a2\n' >&2
grep -Fxq 'promotion_authority external-github-attestation' "${output}/version.manifest"; printf 'DEBUG a3\n' >&2
! grep -Eq 'github-actions|999|v99[.]99[.]99|production_eligible' "${output}/version.manifest"; printf 'DEBUG a4\n' >&2
grep -Fxq 'format pgw-source-snapshot-v1' "${output}/source.manifest"; printf 'DEBUG a5\n' >&2
grep -Fxq 'format pgw-build-proof-v2' "${output}/build-proof.manifest"; printf 'DEBUG a6\n' >&2
grep -Fxq 'deterministic_builds 2' "${output}/build-proof.manifest"; printf 'DEBUG a7\n' >&2
[[ "$(grep -c '^binary ' "${output}/build-proof.manifest")" == 6 ]]; printf 'DEBUG a8\n' >&2
[[ "$(grep -c ' cgo=0 dynamic=absent rebuild=identical proof_sha256=' "${output}/build-proof.manifest")" == 6 ]]; printf 'DEBUG a9\n' >&2
python3 "${ROOT}/deploy/verify_release_candidate.py" "${output}" >/dev/null
printf 'DEBUG checkpoint: build+verify done\n' >&2

actual="$(sha256sum "${output}/release/release.manifest" | awk '{print $1}')"
evidence="${fixture}/evidence"
install -d "${evidence}" "${fixture}/fake-tools"
printf 'redacted fixture transcript: all gates PASS\n' >"${evidence}/rehearsal.transcript"
cat >"${evidence}/rehearsal.manifest" <<EOF
format pgw-rehearsal-v2
release_id test-release-v2
release_manifest_sha256 ${actual}
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
printf 'fixture_upgrade PASS\nfixture_rollback PASS\nfixture_fail_close PASS\n' >"${evidence}/fixture-results.manifest"
printf 'assembly verification fixture\n' >"${evidence}/assembly-verification.tsv"
printf 'isolation fixture\n' >"${evidence}/isolation-identity.tsv"
printf 'lifecycle fixture\n' >"${evidence}/lifecycle-transcript.tsv"
cat >"${fixture}/fake-tools/syft" <<'EOF'
#!/bin/bash
set -Eeuo pipefail
if [[ "${1:-}" == version ]]; then
    printf '{"version":"1.34.2"}\n'
    exit 0
fi
spdx_output=
syft_output=
for argument in "$@"; do
    [[ "${argument}" != spdx-json=* ]] || spdx_output="${argument#spdx-json=}"
    [[ "${argument}" != syft-json=* ]] || syft_output="${argument#syft-json=}"
done
[[ -n "${spdx_output}" && -n "${syft_output}" ]]
printf '{"spdxVersion":"SPDX-2.3","documentNamespace":"https://example.invalid/pgw","packages":[{"name":"pgw"}]}\n' >"${spdx_output}"
source_dir="${2#dir:}"
{
  printf '{"files":['
  first=1
  for binary in "${source_dir}"/*; do
    ((first)) || printf ','
    first=0
    printf '{"executable":{"format":"ELF"},"digests":[{"algorithm":"sha256","value":"%s"}]}' "$(sha256sum "${binary}" | awk '{print $1}')"
  done
  printf ']}\n'
} >"${syft_output}"
EOF
cat >"${fixture}/fake-tools/gitleaks" <<'EOF'
#!/bin/bash
set -Eeuo pipefail
if [[ "${1:-}" == version ]]; then printf '8.28.0\n'; exit 0; fi
report=
while (($#)); do
    if [[ "$1" == --report-path ]]; then report="$2"; shift 2; else shift; fi
done
[[ -n "${report}" ]]
printf '[]\n' >"${report}"
EOF
real_go="$(command -v go)"
cat >"${fixture}/fake-tools/go" <<EOF
#!/bin/bash
set -Eeuo pipefail
if [[ "\${1:-}" == version && "\${2:-}" == -m ]]; then
    case "\$(basename -- "\${3:-}")" in
        syft) printf '\tmod\tgithub.com/anchore/syft\tv1.34.2\th1:test\n'; exit 0 ;;
        gitleaks) printf '\tmod\tgithub.com/zricethezav/gitleaks/v8\tv8.28.0\th1:test\n'; exit 0 ;;
    esac
fi
exec ${real_go@Q} "\$@"
EOF
chmod 0755 "${fixture}/fake-tools/syft" "${fixture}/fake-tools/gitleaks" "${fixture}/fake-tools/go"
(cd "${fixture}/fake-tools" && sha256sum syft gitleaks) >"${evidence}/release-tool-binaries.sha256"
cat >"${evidence}/release-tool-versions.manifest" <<'EOF'
format pgw-release-tool-versions-v1
tool syft v1.34.2
tool gitleaks v8.28.0
EOF

PATH="${fixture}/fake-tools:${PATH}" /bin/bash "${ROOT}/deploy/finalize-release.sh" \
    "${output}" "${evidence}" "${fixture}/candidate" >/dev/null
printf 'DEBUG checkpoint: finalize-release done\n' >&2
(
    cd -- "${fixture}/candidate"
    sha256sum -c SHA256SUMS >/dev/null
)
grep -Fxq 'format pgw-evidence-index-v2' "${fixture}/candidate/evidence.index"
grep -Fxq 'candidate_only true' "${fixture}/candidate/promotion.manifest"
grep -Fxq 'production_promotion_available false' "${fixture}/candidate/promotion.manifest"
grep -Fxq 'required_attestation independent-external-oidc-sigstore' "${fixture}/candidate/promotion.manifest"
grep -Fxq 'subject_count 6' "${fixture}/candidate/sbom-subjects.manifest"
[[ "$(grep -c '^binary ' "${fixture}/candidate/sbom-subjects.manifest")" == 6 ]]
grep -Fxq 'source full' "${fixture}/candidate/secret-scan.coverage"
grep -Fxq 'bundle closed-pre-report' "${fixture}/candidate/secret-scan.coverage"
grep -Fxq 'binary_count 6' "${fixture}/candidate/secret-scan.coverage"
for scan in source binary bundle; do
    jq -e 'type == "array" and length == 0' "${fixture}/candidate/secret-scan-${scan}.json" >/dev/null
done
/bin/bash "${ROOT}/deploy/close-release.sh" "${fixture}/candidate" "${fixture}/candidate.tar" >/dev/null
tar -tf "${fixture}/candidate.tar" | grep -Fxq './promotion.manifest'
printf 'DEBUG checkpoint: close-release done\n' >&2

# A local caller can never turn candidate metadata into production authority.
set +e
PATH="${fixture}/fake-tools:${PATH}" /bin/bash "${ROOT}/deploy/finalize-release.sh" --production \
    "${output}" "${evidence}" "${fixture}/forbidden-production" >/dev/null 2>&1
production_rc=$?
set -e
[[ "${production_rc}" == 65 && ! -e "${fixture}/forbidden-production" ]]
printf 'DEBUG checkpoint: forbidden-production done\n' >&2

# Exact parser tests update the outer trust digest so failure proves the inner
# duplicate/path/self-promotion checks, not merely an old checksum mismatch.
cp -a -- "${output}" "${fixture}/duplicate-manifest"
tail -n1 "${fixture}/duplicate-manifest/release/release.manifest" >>"${fixture}/duplicate-manifest/release/release.manifest"
sed -i "s/^manifest_sha256 .*/manifest_sha256 $(sha256sum "${fixture}/duplicate-manifest/release/release.manifest" | awk '{print $1}')/" \
    "${fixture}/duplicate-manifest/release-trust.manifest"
set +e
python3 "${ROOT}/deploy/verify_release_candidate.py" "${fixture}/duplicate-manifest" >/dev/null 2>&1
duplicate_rc=$?
set -e
[[ "${duplicate_rc}" == 65 ]]
printf 'DEBUG checkpoint: duplicate-manifest done\n' >&2

cp -a -- "${output}" "${fixture}/self-promoted"
sed -i 's/^candidate_only true$/candidate_only false/' "${fixture}/self-promoted/version.manifest"
set +e
python3 "${ROOT}/deploy/verify_release_candidate.py" "${fixture}/self-promoted" >/dev/null 2>&1
self_promoted_rc=$?
set -e
[[ "${self_promoted_rc}" == 65 ]]
printf 'DEBUG checkpoint: self-promoted done\n' >&2

cp -a -- "${output}" "${fixture}/traversal-manifest"
printf 'file %064d 0644 ../escape\n' 0 >>"${fixture}/traversal-manifest/release/release.manifest"
sed -i "s/^manifest_sha256 .*/manifest_sha256 $(sha256sum "${fixture}/traversal-manifest/release/release.manifest" | awk '{print $1}')/" \
    "${fixture}/traversal-manifest/release-trust.manifest"
set +e
python3 "${ROOT}/deploy/verify_release_candidate.py" "${fixture}/traversal-manifest" >/dev/null 2>&1
traversal_rc=$?
set -e
[[ "${traversal_rc}" == 65 ]]
printf 'DEBUG checkpoint: traversal-manifest done\n' >&2

cp -a -- "${evidence}" "${fixture}/special-evidence"
mkfifo "${fixture}/special-evidence/forbidden.fifo"
set +e
PATH="${fixture}/fake-tools:${PATH}" /bin/bash "${ROOT}/deploy/finalize-release.sh" \
    "${output}" "${fixture}/special-evidence" "${fixture}/forbidden-special" >/dev/null 2>&1
special_rc=$?
set -e
[[ "${special_rc}" == 65 && ! -e "${fixture}/forbidden-special" ]]
printf 'DEBUG checkpoint: special-evidence done\n' >&2

cp -a -- "${evidence}" "${fixture}/symlink-evidence"
ln -s rehearsal.transcript "${fixture}/symlink-evidence/forbidden.link"
set +e
PATH="${fixture}/fake-tools:${PATH}" /bin/bash "${ROOT}/deploy/finalize-release.sh" \
    "${output}" "${fixture}/symlink-evidence" "${fixture}/forbidden-symlink" >/dev/null 2>&1
symlink_rc=$?
set -e
[[ "${symlink_rc}" == 65 && ! -e "${fixture}/forbidden-symlink" ]]
printf 'DEBUG checkpoint: symlink-evidence done\n' >&2

/bin/bash "${ROOT}/deploy/tests/attestation_bootstrap_test.sh"
printf 'DEBUG checkpoint: attestation_bootstrap_test done\n' >&2
/bin/bash "${ROOT}/deploy/tests/full_system_trust_bootstrap_test.sh"
printf 'DEBUG checkpoint: full_system_trust_bootstrap_test done\n' >&2
python3 -B "${ROOT}/deploy/tests/full_system_evidence_parser_test.py"
printf 'DEBUG checkpoint: full_system_evidence_parser_test done\n' >&2

printf 'release hermeticity, exact-parser, scan-coverage, closure, and trusted-bootstrap tests: PASS\n'
