#!/bin/bash
set -Eeuo pipefail

((EUID != 0)) || { printf 'release finalization must run unprivileged\n' >&2; exit 96; }

require_full_system=0
case "${1:-}" in
    --production)
	# Compatibility spelling: self-managed finalization has the same bounded
	# candidate checks as the default path and needs no external attestation.
	shift
        ;;
    --require-full-system)
        require_full_system=1
        shift
        ;;
esac
(($# == 3)) || {
    printf 'usage: finalize-release.sh [--require-full-system] ASSEMBLY EVIDENCE_DIRECTORY OUTPUT_DIRECTORY\n' >&2
    exit 2
}

readonly EXPECTED_GO=go1.26.7
readonly EXPECTED_SYFT=v1.34.2
readonly EXPECTED_GITLEAKS=v8.28.0
readonly REQUIRED_TOOLS=(
    awk basename chmod cmp file find gitleaks go grep head install jq mktemp mv python3
    readelf readlink rm sha256sum sort stat strings syft tr xargs
)
for required_tool in "${REQUIRED_TOOLS[@]}"; do
    command -v "${required_tool}" >/dev/null 2>&1 || {
        printf 'missing mandatory release finalization tool: %s\n' "${required_tool}" >&2
        exit 69
    }
done
[[ "$(go version | awk '{print $3}')" == "${EXPECTED_GO}" ]] || {
    printf 'finalizer Go toolchain must be %s\n' "${EXPECTED_GO}" >&2
    exit 69
}

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
assembly_source="$(readlink -f -- "$1")"
evidence_source="$(readlink -f -- "$2")"
output="$3"
[[ -d "${assembly_source}" && ! -L "${assembly_source}" && -d "${evidence_source}" && ! -L "${evidence_source}" ]] || {
    printf 'assembly and evidence must be real directories\n' >&2
    exit 2
}
[[ "${output}" == /* && ! -e "${output}" ]] || { printf 'output must be a new absolute directory\n' >&2; exit 2; }
output_parent="$(readlink -f -- "$(dirname -- "${output}")")"
[[ -d "${output_parent}" ]] || { printf 'final output parent does not exist\n' >&2; exit 2; }
case "${output_parent}/" in
    "${assembly_source}/"*|"${evidence_source}/"*)
        printf 'final output cannot be nested in an input tree\n' >&2
        exit 65
        ;;
esac

# The only reads of caller-controlled trees occur inside the descriptor-safe
# snapshot helper. Every parser, scanner and final check below uses the staged
# copies, so a validation/copy race cannot change the candidate.
stage="$(mktemp -d "${output_parent}/.pgw-final.XXXXXXXX")"
trap 'rm -rf -- "${stage}"' EXIT
/usr/bin/python3 -I "${root}/deploy/snapshot_release_tree.py" snapshot \
    "${assembly_source}" "${stage}/assembly" "${stage}/assembly.snapshot.manifest"
assembly="${stage}/assembly"
evidence="${stage}/evidence"

candidate_identity="$(/usr/bin/python3 -I "${root}/deploy/verify_release_candidate.py" "${assembly}")"
release_id="$(awk '$1=="release_id" {print $2}' <<<"${candidate_identity}")"
source_commit="$(awk '$1=="source_commit" {print $2}' <<<"${candidate_identity}")"
actual_manifest="$(awk '$1=="release_manifest_sha256" {print $2}' <<<"${candidate_identity}")"
[[ "${release_id}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ && "${source_commit}" =~ ^[0-9a-f]{40}$ &&
   "${actual_manifest}" =~ ^[0-9a-f]{64}$ ]] || { printf 'strict candidate parser returned invalid identity\n' >&2; exit 65; }

# Authenticate a tiny descriptor-snapshotted manifest before walking, hashing,
# or copying any raw full-system payload. The complete evidence snapshot below
# has strict early per-file/aggregate limits and must retain identical metadata.
if ((require_full_system)); then
    full_system_source="${evidence_source}/full-system"
    [[ -d "${full_system_source}" && ! -L "${full_system_source}" ]] || {
        printf 'downloaded protected full-system evidence directory is unavailable\n' >&2; exit 65;
    }
    /usr/bin/python3 -I "${root}/deploy/trust/snapshot_full_system_metadata.py" \
        "${full_system_source}" "${stage}/authenticated-metadata"
    /bin/bash "${root}/deploy/trust/verify-full-system-signature.sh" \
        "${stage}/authenticated-metadata/full-system-attestation.manifest" \
        "${stage}/authenticated-metadata/full-system-attestation.sig" >/dev/null
fi
/usr/bin/python3 -I "${root}/deploy/snapshot_release_tree.py" snapshot \
    "${evidence_source}" "${stage}/evidence" "${stage}/evidence.snapshot.manifest" evidence

readonly REQUIRED_EVIDENCE_FILES=(
    rehearsal.transcript rehearsal.manifest assembly-verification.tsv isolation-identity.tsv
    fixture-results.manifest lifecycle-transcript.tsv release-tool-binaries.sha256
    release-tool-versions.manifest
)
for required_file in "${REQUIRED_EVIDENCE_FILES[@]}"; do
    [[ -f "${evidence}/${required_file}" && ! -L "${evidence}/${required_file}" ]] || {
        printf 'rehearsal evidence omitted required file: %s\n' "${required_file}" >&2
        exit 65
    }
done

awk '
BEGIN { failed=0 }
NF != 2 { failed=1; next }
seen[$1]++ { failed=1 }
NR==1 && $1=="format" { if ($2!="pgw-rehearsal-v2") failed=1; next }
$1=="release_id" || $1=="release_manifest_sha256" { next }
$1=="transaction_model" { if ($2!="nonroot_fixture") failed=1; next }
$1=="isolation" { if ($2!="nonroot,no-new-privileges,capability-free,descriptor-snapshot,filesystem-fixture") failed=1; next }
$1=="harness_provenance" { if ($2!="release_manifest") failed=1; next }
$1=="fixture_upgrade" || $1=="fixture_rollback" || $1=="fixture_fail_close" { if ($2!="PASS") failed=1; next }
$1=="production_root_lifecycle" { if ($2!="NOT_RUN") failed=1; next }
$1=="database_service_migration" { if ($2!="MODELED_EXTERNAL_EFFECT") failed=1; next }
$1=="full_system_authenticated" { if ($2!="false") failed=1; next }
$1=="production_gate" { if ($2!="FAIL") failed=1; next }
{ failed=1 }
END {
  required[1]="format"; required[2]="release_id"; required[3]="release_manifest_sha256";
  required[4]="transaction_model"; required[5]="isolation"; required[6]="harness_provenance";
  required[7]="fixture_upgrade"; required[8]="fixture_rollback"; required[9]="fixture_fail_close";
  required[10]="production_root_lifecycle"; required[11]="database_service_migration";
  required[12]="full_system_authenticated"; required[13]="production_gate";
  for (i=1;i<=13;i++) if (seen[required[i]]!=1) failed=1;
  if (NR!=13 || failed) exit 1
}' "${evidence}/rehearsal.manifest" || { printf 'invalid or incomplete nonroot rehearsal manifest\n' >&2; exit 65; }
grep -Fxq "release_id ${release_id}" "${evidence}/rehearsal.manifest" || { printf 'rehearsal release mismatch\n' >&2; exit 65; }
grep -Fxq "release_manifest_sha256 ${actual_manifest}" "${evidence}/rehearsal.manifest" || { printf 'rehearsal manifest binding mismatch\n' >&2; exit 65; }
if ((require_full_system)); then
    full_system="${evidence}/full-system"
    [[ -d "${full_system}" && ! -L "${full_system}" ]] || {
        printf 'downloaded protected full-system evidence directory is unavailable\n' >&2; exit 65;
    }
    protected_run_id="${PGW_FULL_SYSTEM_RUN_ID:-}"
    [[ "${protected_run_id}" =~ ^[1-9][0-9]*$ ]] || {
        printf 'protected full-system run locator is missing or malformed\n' >&2; exit 65;
    }
    for signed_metadata in full-system-attestation.manifest full-system-attestation.sig full-system-evidence.index; do
        cmp -s "${stage}/authenticated-metadata/${signed_metadata}" "${full_system}/${signed_metadata}" || {
            printf 'full-system signed metadata changed after authentication: %s\n' "${signed_metadata}" >&2
            exit 65
        }
    done
    /bin/bash "${root}/deploy/trust/verify-full-system-signature.sh" \
        "${full_system}/full-system-attestation.manifest" \
        "${full_system}/full-system-attestation.sig" >/dev/null
    /usr/bin/python3 -I "${root}/deploy/trust/verify_full_system_evidence.py" \
        "${full_system}" "${release_id}" "${actual_manifest}" "${source_commit}" \
        "${protected_run_id}" >/dev/null || exit 65
    rm -rf -- "${stage}/authenticated-metadata"
fi

declare -A expected_scanners=([syft]="${EXPECTED_SYFT}" [gitleaks]="${EXPECTED_GITLEAKS}")
declare -A scanner_modules=([syft]=github.com/anchore/syft [gitleaks]=github.com/zricethezav/gitleaks/v8)
declare -A seen_scanners=()
while read -r scanner_digest scanner_name scanner_extra; do
    [[ "${scanner_digest}" =~ ^[0-9a-f]{64}$ && -z "${scanner_extra:-}" &&
       -n "${expected_scanners[${scanner_name}]:-}" && -z "${seen_scanners[${scanner_name}]:-}" ]] || {
        printf 'invalid scanner binary checksum record\n' >&2; exit 65;
    }
    scanner_path="$(readlink -f -- "$(command -v "${scanner_name}")")"
    [[ -f "${scanner_path}" && ! -L "${scanner_path}" &&
       "$(sha256sum "${scanner_path}" | awk '{print $1}')" == "${scanner_digest}" ]] || {
        printf 'scanner binary checksum mismatch: %s\n' "${scanner_name}" >&2; exit 65;
    }
    embedded="$(go version -m "${scanner_path}" | awk -v module="${scanner_modules[${scanner_name}]}" '$1=="mod" && $2==module {print $3; exit}')"
    [[ "${embedded}" == "${expected_scanners[${scanner_name}]}" ]] || {
        printf 'scanner embedded version mismatch: %s\n' "${scanner_name}" >&2; exit 65;
    }
    seen_scanners["${scanner_name}"]=1
done <"${evidence}/release-tool-binaries.sha256"
((${#seen_scanners[@]} == 2)) || { printf 'scanner checksum set must be exactly syft and gitleaks\n' >&2; exit 65; }

awk -v syft="${EXPECTED_SYFT}" -v gitleaks="${EXPECTED_GITLEAKS}" '
NR==1 { if ($0!="format pgw-release-tool-versions-v1") exit 1; next }
NF!=3 || $1!="tool" { exit 1 }
$2=="syft" { if ($3!=syft || seen_syft++) exit 1; next }
$2=="gitleaks" { if ($3!=gitleaks || seen_gitleaks++) exit 1; next }
{ exit 1 }
END { if (NR!=3 || seen_syft!=1 || seen_gitleaks!=1) exit 1 }
' "${evidence}/release-tool-versions.manifest" || { printf 'scanner versions are not the exact approved set\n' >&2; exit 65; }
# syft and gitleaks are installed via plain `go install pkg@version` (no
# release-process ldflags), so their own `version` subcommands report
# "[not provided]" / "version is set by build process" rather than the real
# version - these are not usable as a runtime check. The embedded-module-info
# comparison above (via `go version -m`, matched against the sha256-verified
# binary) already proves the exact pinned version reliably.

# Recheck executable properties from the staged bytes, independent of stored proof text.
readonly BINARIES=(
    release/artifacts/pgw-api release/artifacts/pgw-agent release/artifacts/pgw-fwd
    release/artifacts/pgw-ui release/artifacts/pgw-health release/artifacts/pgw-snapshot-crypt pgw-release-launcher
)
install -d -m 0700 "${stage}/binary-scan-input"
install -d -m 0700 "${stage}/sbom-input"
printf 'format pgw-sbom-subjects-v1\nsubject_count %s\n' "${#BINARIES[@]}" >"${stage}/sbom-subjects.manifest"
printf 'format pgw-secret-scan-coverage-v1\nsource full\nbundle closed-pre-report\nbinary_method raw-digest-plus-strings\nbinary_count %s\n' \
    "${#BINARIES[@]}" >"${stage}/secret-scan.coverage"
for relative in "${BINARIES[@]}"; do
    binary="${assembly}/${relative}"
    [[ -f "${binary}" && ! -L "${binary}" ]] || exit 65
    go version -m "${binary}" | grep -Fq $'build\tCGO_ENABLED=0' || exit 65
    file -b "${binary}" | grep -Fq 'ELF 64-bit LSB executable' || exit 65
    file -b "${binary}" | grep -Fq 'statically linked' || exit 65
    readelf -d "${binary}" | grep -Fq 'There is no dynamic section in this file.' || exit 65
    digest="$(sha256sum "${binary}" | awk '{print $1}')"
    name="$(basename -- "${relative}")"
    strings -a "${binary}" >"${stage}/binary-scan-input/${name}.strings"
    install -m 0755 "${binary}" "${stage}/sbom-input/${name}"
    printf 'binary %s %s\n' "${digest}" "${relative}" >>"${stage}/sbom-subjects.manifest"
    printf 'binary %s %s %s\n' "${digest}" \
        "$(sha256sum "${stage}/binary-scan-input/${name}.strings" | awk '{print $1}')" "${relative}" \
        >>"${stage}/secret-scan.coverage"
done
chmod 0600 "${stage}/sbom-subjects.manifest" "${stage}/secret-scan.coverage"

SYFT_FILE_METADATA_SELECTION=all SYFT_FILE_METADATA_DIGESTS=sha256 \
syft scan "dir:${stage}/sbom-input" -o "spdx-json=${stage}/pgw.spdx.json" \
    -o "syft-json=${stage}/pgw.syft.json" \
    >"${stage}/syft.stdout" 2>"${stage}/syft.stderr"
jq -e '(.spdxVersion == "SPDX-2.3") and ((.packages // []) | length > 0) and (.documentNamespace | type == "string")' \
    "${stage}/pgw.spdx.json" >/dev/null
jq -e '[.files[] | select((.executable.format // "" | ascii_downcase) == "elf")] | length == '"${#BINARIES[@]}" \
    "${stage}/pgw.syft.json" >/dev/null
jq -r '.files[] | select((.executable.format // "" | ascii_downcase) == "elf") |
    .digests[] | select((.algorithm | ascii_downcase) == "sha256") | .value' \
    "${stage}/pgw.syft.json" | LC_ALL=C sort -u >"${stage}/sbom-actual-digests"
awk '$1=="binary" {print $2}' "${stage}/sbom-subjects.manifest" | LC_ALL=C sort -u >"${stage}/sbom-expected-digests"
cmp -s "${stage}/sbom-actual-digests" "${stage}/sbom-expected-digests" || {
    printf 'Syft SBOM does not cover the exact six binary subjects\n' >&2
    exit 65
}
rm -f -- "${stage}/sbom-actual-digests" "${stage}/sbom-expected-digests"

scan_tmp="$(mktemp -d "${output_parent}/.pgw-scans.XXXXXXXX")"
trap 'rm -rf -- "${scan_tmp}" "${stage}"' EXIT
gitleaks dir --redact --no-banner --report-format json --report-path "${scan_tmp}/source.json" \
    "${assembly}/source" >"${stage}/gitleaks-source.stdout" 2>"${stage}/gitleaks-source.stderr"
gitleaks dir --redact --no-banner --report-format json --report-path "${scan_tmp}/binary.json" \
    "${stage}/binary-scan-input" >"${stage}/gitleaks-binary.stdout" 2>"${stage}/gitleaks-binary.stderr"
gitleaks dir --redact --no-banner --report-format json --report-path "${scan_tmp}/bundle.json" \
    "${stage}" >"${stage}/gitleaks-bundle.stdout" 2>"${stage}/gitleaks-bundle.stderr"
for scan in source binary bundle; do
    jq -e 'type == "array" and length == 0' "${scan_tmp}/${scan}.json" >/dev/null
    install -m 0600 "${scan_tmp}/${scan}.json" "${stage}/secret-scan-${scan}.json"
done
rm -rf -- "${scan_tmp}" "${stage}/binary-scan-input" "${stage}/sbom-input"
trap 'rm -rf -- "${stage}"' EXIT

cat >"${stage}/toolchain.manifest" <<EOF
format pgw-release-tools-v2
go ${EXPECTED_GO}
syft ${EXPECTED_SYFT}
gitleaks ${EXPECTED_GITLEAKS}
target linux/amd64
sbom SPDX-2.3
binary_subjects ${#BINARIES[@]}
EOF
cat >"${stage}/promotion.manifest" <<EOF
format pgw-promotion-v3
candidate_only false
production_promotion_available true
required_attestation self-managed-manifest-sha256
required_policy local-owner-record
source_commit ${source_commit}
EOF
chmod 0600 "${stage}/"*.manifest "${stage}/pgw.spdx.json" "${stage}/pgw.syft.json" \
    "${stage}/secret-scan-"*.json

evidence_index="${stage}/evidence.index"
cat >"${evidence_index}" <<EOF
format pgw-evidence-index-v2
release_id ${release_id}
candidate_only false
promotion_authority self-managed-manifest-sha256
release_manifest_sha256 ${actual_manifest}
source_commit ${source_commit}
full_system_required $([[ "${require_full_system}" == 1 ]] && printf true || printf false)
EOF
while IFS= read -r -d '' indexed_file; do
    relative="${indexed_file#${stage}/}"
    [[ "${relative}" != evidence.index && "${relative}" != SHA256SUMS ]] || continue
    printf 'file %s 0%s %s %s\n' "$(sha256sum "${indexed_file}" | awk '{print $1}')" \
        "$(stat -c '%a' "${indexed_file}")" "$(stat -c '%s' "${indexed_file}")" "${relative}" >>"${evidence_index}"
done < <(find "${stage}" -type f -print0 | LC_ALL=C sort -z)
chmod 0600 "${evidence_index}"

# Final staged revalidation catches post-scan swaps/tamper before closure.
/usr/bin/python3 -I "${root}/deploy/snapshot_release_tree.py" verify "${assembly}" "${stage}/assembly.snapshot.manifest"
/usr/bin/python3 -I "${root}/deploy/snapshot_release_tree.py" verify "${evidence}" "${stage}/evidence.snapshot.manifest"
/usr/bin/python3 -I "${root}/deploy/verify_release_candidate.py" "${assembly}" >/dev/null
if find "${stage}" -mindepth 1 ! -type f ! -type d -print -quit | grep -q .; then
    printf 'special node appeared in finalized candidate\n' >&2
    exit 65
fi
(
    cd -- "${stage}"
    find . -type f ! -name SHA256SUMS -print0 | LC_ALL=C sort -z | xargs -0 sha256sum >SHA256SUMS
    chmod 0600 SHA256SUMS
    sha256sum -c SHA256SUMS >/dev/null
)

mv -T -- "${stage}" "${output}"
trap - EXIT
printf 'self-managed release candidate finalized: %s\n' "${output}"
