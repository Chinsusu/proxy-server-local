#!/bin/bash
set -Eeuo pipefail

((EUID != 0)) || { printf 'release assembly must run unprivileged\n' >&2; exit 96; }

allow_dirty=0
requested_commit=
while (($# > 0)); do
    case "$1" in
        --rehearsal-dirty) allow_dirty=1; shift ;;
        --source-commit)
            (($# >= 2)) || { printf 'missing --source-commit value\n' >&2; exit 2; }
            requested_commit="$2"
            shift 2
            ;;
        --) shift; break ;;
        -*) printf 'unknown option: %s\n' "$1" >&2; exit 2 ;;
        *) break ;;
    esac
done
(($# == 2)) || {
    printf 'usage: build-release.sh [--rehearsal-dirty] [--source-commit SHA] RELEASE_ID OUTPUT_DIRECTORY\n' >&2
    exit 2
}
release_id="$1"
output="$2"
[[ "${release_id}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || { printf 'invalid release id\n' >&2; exit 2; }
[[ "${output}" == /* && ! -e "${output}" ]] || { printf 'output must be a new absolute directory\n' >&2; exit 2; }

readonly REQUIRED_TOOLS=(
    awk basename chmod cmp date dirname env file find git go grep install mktemp mv
    readelf rm sha256sum sort stat tar tee tr
)
for required_tool in "${REQUIRED_TOOLS[@]}"; do
    command -v "${required_tool}" >/dev/null 2>&1 || {
        printf 'missing release build tool: %s\n' "${required_tool}" >&2
        exit 69
    }
done

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
git -C "${root}" rev-parse --is-inside-work-tree >/dev/null 2>&1 || {
    printf 'release source must be a Git worktree\n' >&2
    exit 65
}

# These names identify runtime credentials/state, never reviewable source.
# Keep this predicate before both archive/copy paths so a force-added file and
# a dirty rehearsal input have the same fail-closed boundary.
forbidden_source_path() {
    local path="$1"
    [[ "${path}" =~ (^|/)[.]pgw-transaction[.][^/]+(/|$) ]] && return 0
    [[ "${path}" =~ (^|/)(proxy_password|proxy_username|ui[.]key|ui_proxy_token|snapshot-encryption[.]key|snapshot[.]hmac|admin_pass_hash|jwt_secret|agent[.]token|secrets[.]key|pgw[.]db)$ ]] && return 0
    [[ "${path}" =~ (^|/)(runtime|runtime-state|state|credentials|credential-generations|backups)(/|$) ]] && return 0
    [[ "${path}" =~ (^|/)artifacts(/|$) ]] && return 0
    return 1
}

git -C "${root}" diff --quiet --diff-filter=U -- || {
    printf 'unmerged source is never releasable\n' >&2
    exit 65
}

head_commit="$(git -C "${root}" rev-parse HEAD)"
source_commit="${requested_commit:-${head_commit}}"
[[ "${source_commit}" =~ ^[0-9a-f]{40}$ ]] || { printf 'source commit must be a full lowercase Git SHA\n' >&2; exit 65; }
git -C "${root}" cat-file -e "${source_commit}^{commit}" 2>/dev/null || {
    printf 'source commit is not present in this repository\n' >&2
    exit 65
}
source_commit="$(git -C "${root}" rev-parse "${source_commit}^{commit}")"
[[ "${source_commit}" == "${requested_commit:-${head_commit}}" ]] || {
    printf 'source commit did not resolve exactly\n' >&2
    exit 65
}
source_tree="$(git -C "${root}" show -s --format=%T "${source_commit}")"
[[ "${source_tree}" =~ ^[0-9a-f]{40}$ ]] || { printf 'invalid source tree identity\n' >&2; exit 65; }

# Generated caches, local backups, build trees, and runtime state are never
# release source. Check the committed tree before archive/copy; force-adding
# one must fail assembly rather than silently becoming a signed candidate.
while IFS= read -r committed_path; do
    if forbidden_source_path "${committed_path}" || \
       [[ "${committed_path}" =~ (^|/)(__pycache__/|[^/]+[.]py[co]$|[^/]+[.](bak|backup)([.][^/]+)?$|build(/|$)) ]]; then
        printf 'release source contains forbidden generated/cache/backup/runtime path\n' >&2
        exit 65
    fi
done < <(git -C "${root}" ls-tree -r --name-only "${source_commit}")

# The transaction fixture is intentionally root-ignored, so Git's ordinary
# dirty-file enumeration will not report it. Reject it directly by name; this
# neither reads its contents nor permits it into a candidate.
transaction_workspace="$(find "${root}" -path "${root}/.git" -prune -o -type d -name '.pgw-transaction.*' -print -quit)"
if [[ -n "${transaction_workspace}" ]]; then
    printf 'release source contains forbidden transaction workspace path\n' >&2
    exit 65
fi

source_dirty=false
if [[ -n "$(git -C "${root}" status --porcelain=v1 --untracked-files=all)" ]]; then
    source_dirty=true
fi
if [[ "${source_dirty}" == true && "${allow_dirty}" == 0 ]]; then
    printf 'dirty release source is forbidden; --rehearsal-dirty creates a local-only candidate\n' >&2
    exit 65
fi
if [[ "${source_dirty}" == true && "${head_commit}" != "${source_commit}" ]]; then
    printf 'dirty rehearsal can only snapshot HEAD\n' >&2
    exit 65
fi

parent="$(dirname -- "${output}")"
[[ -d "${parent}" ]] || { printf 'output parent does not exist\n' >&2; exit 2; }
stage="$(mktemp -d "${parent}/.pgw-release.${release_id}.XXXXXXXX")"
trap 'rm -rf -- "${stage}"' EXIT
install -d -m 0755 "${stage}/source" "${stage}/release/artifacts" \
    "${stage}/build-proof" "${stage}/.go/home" "${stage}/.go/tmp" \
    "${stage}/.go/modcache" "${stage}/.go/build-a" "${stage}/.go/build-b"

# Clean candidates are always built from a fresh Git object export, never from
# the caller's checkout. Dirty mode exists only for local rehearsal and still
# snapshots a closed, revalidated file set before executing any source.
if [[ "${source_dirty}" == false ]]; then
    git -C "${root}" archive --format=tar "${source_commit}" | tar -xf - -C "${stage}/source"
else
    dirty_list="$(mktemp "${parent}/.pgw-dirty-files.XXXXXXXX")"
    trap 'rm -f -- "${dirty_list}"; rm -rf -- "${stage}"' EXIT
    git -C "${root}" ls-files --cached --others --exclude-standard -z | LC_ALL=C sort -z \
        | while IFS= read -r -d '' dirty_path; do
            if forbidden_source_path "${dirty_path}"; then
                printf 'dirty source contains forbidden transaction/credential/runtime path\n' >&2
                exit 65
            fi
            [[ -e "${root}/${dirty_path}" || -L "${root}/${dirty_path}" ]] || continue
            [[ -f "${root}/${dirty_path}" && ! -L "${root}/${dirty_path}" ]] || {
                printf 'dirty source contains a symlink or special node: %s\n' "${dirty_path}" >&2
                exit 65
            }
            printf '%s\0' "${dirty_path}"
        done >"${dirty_list}"
    (cd -- "${root}" && tar --null --files-from="${dirty_list}" --no-recursion -cf -) | tar -xf - -C "${stage}/source"
    rm -f -- "${dirty_list}"
    trap 'rm -rf -- "${stage}"' EXIT
fi
if find "${stage}/source" -mindepth 1 ! -type f ! -type d -print -quit | grep -q .; then
    printf 'source export contains a symlink or special node\n' >&2
    exit 65
fi

source_manifest="${stage}/source.manifest"
printf 'format pgw-source-snapshot-v1\ncommit %s\ntree %s\ndirty %s\n' \
    "${source_commit}" "${source_tree}" "${source_dirty}" >"${source_manifest}"
while IFS= read -r -d '' source_file; do
    relative="${source_file#${stage}/source/}"
    [[ "${relative}" =~ ^[A-Za-z0-9._@+~-]+(/[A-Za-z0-9._@+~-]+)*$ && "${relative}" != *'..'* ]] || {
        printf 'unsafe source path: %s\n' "${relative}" >&2
        exit 65
    }
    printf 'file %s 0%s %s\n' "$(sha256sum "${source_file}" | awk '{print $1}')" \
        "$(stat -c '%a' "${source_file}")" "${relative}" >>"${source_manifest}"
done < <(find "${stage}/source" -type f -print0 | LC_ALL=C sort -z)
chmod 0600 "${source_manifest}"

expected_go="$(awk '$1=="toolchain" {print $2}' "${stage}/source/go.mod")"
[[ "${expected_go}" =~ ^go1[.][0-9]+[.][0-9]+$ ]] || { printf 'go.mod must pin an exact toolchain\n' >&2; exit 65; }
actual_go="$(go version | awk '{print $3}')"
[[ "${actual_go}" == "${expected_go}" ]] || {
    printf 'release toolchain mismatch: expected %s, got %s\n' "${expected_go}" "${actual_go}" >&2
    exit 69
}
goroot="$(GOENV=off GOTOOLCHAIN=local go env GOROOT)"
tool_path="$(dirname -- "$(command -v go)"):/usr/bin:/bin"
run_go() {
    local cache="$1" proxy="$2"
    shift 2
    # -modcacherw: this modcache is private to ${stage} and torn down by the
    # EXIT trap below immediately after this build finishes. Go's normal
    # read-only module cache protects a persistent, shared cache across
    # processes; that protection buys nothing here and only makes the
    # teardown rm -rf fail on read-only extracted module files.
    env -i PATH="${tool_path}" HOME="${stage}/.go/home" TMPDIR="${stage}/.go/tmp" \
        GOROOT="${goroot}" GOENV=off GOTOOLCHAIN=local GOWORK=off GOOS=linux GOARCH=amd64 \
        CGO_ENABLED=0 GOFLAGS=-modcacherw GOPROXY="${proxy}" GOSUMDB=sum.golang.org \
        GOMODCACHE="${stage}/.go/modcache" GOCACHE="${cache}" "$@"
}

# Download under go.sum/SumDB control, then prove and build from the exact same
# module cache with network disabled. No ambient GOENV, GOFLAGS, GOWORK, HOME,
# proxy, compiler or CGO settings cross this boundary.
(cd -- "${stage}/source" && run_go "${stage}/.go/build-a" "https://proxy.golang.org,direct" go mod download all)
(cd -- "${stage}/source" && run_go "${stage}/.go/build-a" off go mod verify) \
    | tee "${stage}/build-proof/go-mod-verify.txt"
grep -Fxq 'all modules verified' "${stage}/build-proof/go-mod-verify.txt" || {
    printf 'go mod verify did not produce the required success proof\n' >&2
    exit 65
}

readonly BUILD_FLAGS=(-trimpath -buildvcs=false '-ldflags=-s -w')
commands=(api agent fwd ui health snapshot-crypt)
for command_name in "${commands[@]}"; do
    (cd -- "${stage}/source" && run_go "${stage}/.go/build-a" off go build "${BUILD_FLAGS[@]}" \
        -o "${stage}/release/artifacts/pgw-${command_name}" "./cmd/${command_name}")
    (cd -- "${stage}/source" && run_go "${stage}/.go/build-b" off go build "${BUILD_FLAGS[@]}" \
        -o "${stage}/build-proof/pgw-${command_name}.rebuild" "./cmd/${command_name}")
    cmp -s "${stage}/release/artifacts/pgw-${command_name}" "${stage}/build-proof/pgw-${command_name}.rebuild" || {
        printf 'non-deterministic rebuild: pgw-%s\n' "${command_name}" >&2
        exit 65
    }
    rm -f -- "${stage}/build-proof/pgw-${command_name}.rebuild"
    chmod 0755 "${stage}/release/artifacts/pgw-${command_name}"
done
(cd -- "${stage}/source" && run_go "${stage}/.go/build-a" off go build "${BUILD_FLAGS[@]}" \
    -o "${stage}/pgw-release-launcher" ./deploy/launcher)
(cd -- "${stage}/source" && run_go "${stage}/.go/build-b" off go build "${BUILD_FLAGS[@]}" \
    -o "${stage}/build-proof/pgw-release-launcher.rebuild" ./deploy/launcher)
cmp -s "${stage}/pgw-release-launcher" "${stage}/build-proof/pgw-release-launcher.rebuild" || {
    printf 'non-deterministic rebuild: pgw-release-launcher\n' >&2
    exit 65
}
rm -f -- "${stage}/build-proof/pgw-release-launcher.rebuild"
chmod 0755 "${stage}/pgw-release-launcher"

readonly RELEASE_FILES=(
    deploy/install-pgw.sh
    deploy/rehearse-release.sh
    deploy/install-pgw-base.sh deploy/pgw-verify-base.sh deploy/pgw-verify-ui-bind.sh deploy/restore_snapshot.py deploy/snapshot_payload.py deploy/nftables.conf deploy/sysctl-pgw.conf
    deploy/tests/installer_harness.sh deploy/tests/installer_transaction_test.sh
    deploy/tests/release_launcher_root_test.sh deploy/tests/lifecycle_fake.sh
    deploy/tests/release_snapshot.py deploy/tests/restore_crash_driver.py
    deploy/sysusers.d/pgw.conf deploy/tmpfiles.d/pgw.conf
    deploy/polkit-1/rules.d/50-pgw-agent-forwarder.rules
    deploy/systemd/pgw-api.service deploy/systemd/pgw-agent.service deploy/systemd/pgw-fwd@.service
    deploy/systemd/pgw-ui.service deploy/systemd/pgw-health.service
    deploy/systemd/nftables.service.d/pgw.conf deploy/systemd/systemd-sysctl.service.d/pgw.conf
    deploy/ui-assets.sha256 web/static/app.js web/static/styles.css web/static/login.js web/static/layout.css
)
for relative in "${RELEASE_FILES[@]}"; do
    [[ -f "${stage}/source/${relative}" ]] || { printf 'release input missing from source snapshot: %s\n' "${relative}" >&2; exit 65; }
    install -d -m 0755 "${stage}/release/$(dirname -- "${relative}")"
    mode=0644
    [[ "${relative}" == *.sh ]] && mode=0755
    install -m "${mode}" "${stage}/source/${relative}" "${stage}/release/${relative}"
done

manifest="${stage}/release/release.manifest"
printf 'format pgw-release-v1\n' >"${manifest}"
for relative in deploy/install-pgw.sh deploy/rehearse-release.sh \
    artifacts/pgw-api artifacts/pgw-agent artifacts/pgw-fwd artifacts/pgw-ui artifacts/pgw-health artifacts/pgw-snapshot-crypt \
    "${RELEASE_FILES[@]:2}"; do
    printf 'file %s 0%s %s\n' "$(sha256sum "${stage}/release/${relative}" | awk '{print $1}')" \
        "$(stat -c '%a' "${stage}/release/${relative}")" "${relative}" >>"${manifest}"
done
chmod 0600 "${manifest}"
manifest_digest="$(sha256sum "${manifest}" | awk '{print $1}')"
cat >"${stage}/release-trust.manifest" <<EOF
format pgw-trust-v1
release_id ${release_id}
manifest_sha256 ${manifest_digest}
EOF
chmod 0600 "${stage}/release-trust.manifest"

source_epoch="$(git -C "${root}" show -s --format=%ct "${source_commit}")"
source_time="$(date -u -d "@${source_epoch}" '+%Y-%m-%dT%H:%M:%SZ')"
go_module="$(awk '$1=="module" {print $2; exit}' "${stage}/source/go.mod")"
cat >"${stage}/version.manifest" <<EOF
format pgw-version-v2
release_id ${release_id}
candidate_only false
promotion_authority self-managed-manifest-sha256
source_commit ${source_commit}
source_tree ${source_tree}
source_dirty ${source_dirty}
source_commit_time ${source_time}
go_module ${go_module}
go_version ${actual_go}
target linux/amd64
cgo_enabled 0
build_flags -trimpath,-buildvcs=false,-ldflags=-s_-w
module_verification same-run-offline
deterministic_rebuilds 2
release_manifest_sha256 ${manifest_digest}
launcher_sha256 $(sha256sum "${stage}/pgw-release-launcher" | awk '{print $1}')
EOF
chmod 0600 "${stage}/version.manifest"

migration_manifest="${stage}/migration.manifest"
printf 'format pgw-migrations-v1\n' >"${migration_manifest}"
migration_count=0
while IFS= read -r migration_path; do
    migration_name="$(basename -- "${migration_path}")"
    migration_version="${migration_name%%_*}"
    [[ "${migration_version}" =~ ^[0-9]{4}$ ]] || { printf 'invalid migration name: %s\n' "${migration_name}" >&2; exit 65; }
    numeric_version=$((10#${migration_version}))
    ((numeric_version == migration_count + 1)) || { printf 'migration versions must be contiguous from 1\n' >&2; exit 65; }
    printf 'migration %d %s %s\n' "${numeric_version}" \
        "$(sha256sum "${migration_path}" | awk '{print $1}')" "${migration_name}" >>"${migration_manifest}"
    migration_count="${numeric_version}"
done < <(find "${stage}/source/internal/persistence/sqlite/migrations" -maxdepth 1 -type f -name '*.sql' -print | LC_ALL=C sort)
((migration_count > 0)) || { printf 'release contains no SQLite migrations\n' >&2; exit 65; }
sed -i "1a schema_target ${migration_count}\nmigration_count ${migration_count}" "${migration_manifest}"
chmod 0600 "${migration_manifest}"

proof_manifest="${stage}/build-proof.manifest"
printf 'format pgw-build-proof-v2\nmodule_verify_sha256 %s\ndeterministic_builds 2\n' \
    "$(sha256sum "${stage}/build-proof/go-mod-verify.txt" | awk '{print $1}')" >"${proof_manifest}"
for binary_relative in release/artifacts/pgw-api release/artifacts/pgw-agent \
    release/artifacts/pgw-fwd release/artifacts/pgw-ui release/artifacts/pgw-health release/artifacts/pgw-snapshot-crypt pgw-release-launcher; do
    binary="${stage}/${binary_relative}"
    proof_name="$(basename -- "${binary_relative}")"
    go version -m "${binary}" >"${stage}/build-proof/${proof_name}.go-version.txt"
    file -b "${binary}" >"${stage}/build-proof/${proof_name}.file.txt"
    readelf -h "${binary}" >"${stage}/build-proof/${proof_name}.elf-header.txt"
    readelf -d "${binary}" >"${stage}/build-proof/${proof_name}.elf-dynamic.txt"
    grep -Fq $'build\tCGO_ENABLED=0' "${stage}/build-proof/${proof_name}.go-version.txt" || exit 65
    grep -Fq 'ELF 64-bit LSB executable' "${stage}/build-proof/${proof_name}.file.txt" || exit 65
    grep -Fq 'statically linked' "${stage}/build-proof/${proof_name}.file.txt" || exit 65
    grep -Fq 'There is no dynamic section in this file.' "${stage}/build-proof/${proof_name}.elf-dynamic.txt" || exit 65
    proof_digest="$({
        for suffix in go-version.txt file.txt elf-header.txt elf-dynamic.txt; do
            printf '%s\0' "${suffix}"
            sha256sum "${stage}/build-proof/${proof_name}.${suffix}" | awk '{print $1}' | tr -d '\n'
            printf '\0'
        done
    } | sha256sum | awk '{print $1}')"
    printf 'binary %s %s cgo=0 dynamic=absent rebuild=identical proof_sha256=%s\n' \
        "$(sha256sum "${binary}" | awk '{print $1}')" "${binary_relative}" "${proof_digest}" >>"${proof_manifest}"
done
chmod 0600 "${proof_manifest}"
find "${stage}/build-proof" -type f -exec chmod 0600 {} +

# Build caches are never release inputs. Revalidate the exported source after
# all builds so mutation by generators, hooks, or concurrent processes fails.
rm -rf -- "${stage}/.go"
while read -r kind digest mode relative extra; do
    [[ "${kind}" == format || "${kind}" == commit || "${kind}" == tree || "${kind}" == dirty ]] && continue
    [[ "${kind}" == file && -z "${extra:-}" && -f "${stage}/source/${relative}" && ! -L "${stage}/source/${relative}" ]] || exit 65
    [[ "$(sha256sum "${stage}/source/${relative}" | awk '{print $1}')" == "${digest}" && \
       "0$(stat -c '%a' "${stage}/source/${relative}")" == "${mode}" ]] || {
        printf 'source snapshot changed during build: %s\n' "${relative}" >&2
        exit 65
    }
done <"${source_manifest}"

mv -T -- "${stage}" "${output}"
trap - EXIT
printf 'release candidate assembled: %s\n' "${output}"
printf 'source commit: %s\n' "${source_commit}"
printf 'candidate only: true\n'
