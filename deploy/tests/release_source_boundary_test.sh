#!/bin/bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
((EUID != 0)) || { printf 'release source boundary test: SKIP root\n'; exit 0; }

fixture="$(mktemp -d)"
trap 'rm -rf -- "${fixture}"' EXIT
tool_bin="${fixture}/tools"
mkdir -p -- "${tool_bin}"
chmod 0700 -- "${tool_bin}" 2>/dev/null || true
# This test proves the pre-copy admission boundary and never reaches ELF
# inspection. Supply readelf on Windows/Git-Bash hosts that lack it so the
# portable negative oracle still reaches that boundary.
printf '#!/bin/bash\nexit 0\n' >"${tool_bin}/readelf"
chmod 0700 "${tool_bin}/readelf" 2>/dev/null || true

make_dummy_paths() {
    local base="$1"
    mkdir -p -- "${base}"
    chmod 0700 -- "${base}" 2>/dev/null || true
    for name in proxy_password proxy_username ui.key ui_proxy_token snapshot-encryption.key snapshot.hmac \
        admin_pass_hash jwt_secret agent.token secrets.key pgw.db; do
        printf 'fixture-boundary-only\n' >"${base}/${name}"
    done
}

# The caller's candidate worktree can be dirty by design. A clone is used to
# isolate each admission case, then receives only the boundary implementation
# under test; no fixture credentials are copied from the caller.
clone_boundary_repo() {
    local destination="$1" deleted
    git clone -q --no-hardlinks --no-checkout "${ROOT}" "${destination}"
    git -C "${destination}" read-tree HEAD
    # Remove every source deletion from the temporary index before checkout.
    # This avoids materializing obsolete tracked binaries/gitlinks and makes
    # the fixture exercise the candidate tree, not the historical baseline.
    while IFS= read -r -d '' deleted; do
        git -C "${destination}" update-index --force-remove -- "${deleted}"
    done < <(git -C "${ROOT}" diff HEAD --name-only --diff-filter=D -z --)
    git -C "${destination}" checkout-index -a
    install -m 0755 "${ROOT}/deploy/build-release.sh" "${destination}/deploy/build-release.sh"
    cp -- "${ROOT}/.gitignore" "${destination}/.gitignore"
    # The baseline commit still contains legacy backup files that this change
    # intentionally deletes. Reproduce those deletions in the isolated clone
    # so each case exercises the boundary under test rather than an unrelated
    # forbidden path from the historical tree.
    git -C "${destination}" add deploy/build-release.sh .gitignore
    git -C "${destination}" -c user.name=boundary -c user.email=boundary@example.invalid \
        commit -qm 'install source boundary under test'
}

assert_rejected() {
    local repo="$1" output="$2" expected="$3" err rc
    err="${output}.err"
    set +e
    (cd -- "${repo}" && PATH="${tool_bin}:${PATH}" /bin/bash deploy/build-release.sh --rehearsal-dirty source-boundary "${output}") \
        >/dev/null 2>"${err}"
    rc=$?
    set -e
    [[ "${rc}" == 65 && ! -e "${output}" ]] || {
        printf 'release source boundary rejection failed: rc=%s output=%s\n' "${rc}" "${output}" >&2
        return 1
    }
    grep -Fq -- "${expected}" "${err}" || {
        printf 'release source boundary rejection reported an unexpected reason:\n' >&2
        cat -- "${err}" >&2
        return 1
    }
}

# A force-added transaction tree must be rejected from the committed source,
# before Git archive can copy it. The files are names only; their contents are
# not relevant to this source-admission boundary.
committed_repo="${fixture}/committed"
clone_boundary_repo "${committed_repo}"
make_dummy_paths "${committed_repo}/.pgw-transaction.forced"
git -C "${committed_repo}" add -f .pgw-transaction.forced
git -C "${committed_repo}" -c user.name=boundary -c user.email=boundary@example.invalid \
    commit -qm 'force-added transaction fixture'
assert_rejected "${committed_repo}" "${fixture}/committed-output" \
    'release source contains forbidden generated/cache/backup/runtime path'

# Ignored transaction fixtures are intentionally absent from ordinary Git
# dirty enumeration; the builder must still reject the path before copying.
ignored_repo="${fixture}/ignored"
clone_boundary_repo "${ignored_repo}"
make_dummy_paths "${ignored_repo}/.pgw-transaction.dirty"
assert_rejected "${ignored_repo}" "${fixture}/ignored-output" \
    'release source contains forbidden transaction workspace path'

# Dirty non-ignored runtime/credential names exercise the dirty collection
# predicate itself. Keep every credential/state class named in this one
# fixture so a future broadening cannot silently omit one from the test data.
dirty_repo="${fixture}/dirty"
clone_boundary_repo "${dirty_repo}"
make_dummy_paths "${dirty_repo}/dirty-runtime-state"
assert_rejected "${dirty_repo}" "${fixture}/dirty-output" \
    'dirty source contains forbidden transaction/credential/runtime path'

# Exercise every credential filename in isolation. The neutral path avoids the
# transaction/runtime predicates masking an omitted filename in either source
# collection mode.
credential_names=(
    proxy_password proxy_username ui.key ui_proxy_token snapshot-encryption.key
    snapshot.hmac admin_pass_hash jwt_secret agent.token secrets.key pgw.db
)
for credential_name in "${credential_names[@]}"; do
    committed_name_repo="${fixture}/committed-${credential_name//./_}"
    clone_boundary_repo "${committed_name_repo}"
    mkdir -p -- "${committed_name_repo}/neutral"
    chmod 0700 -- "${committed_name_repo}/neutral" 2>/dev/null || true
    printf 'fixture-boundary-only\n' >"${committed_name_repo}/neutral/${credential_name}"
    git -C "${committed_name_repo}" add -f "neutral/${credential_name}"
    git -C "${committed_name_repo}" -c user.name=boundary -c user.email=boundary@example.invalid \
        commit -qm "force-added ${credential_name}"
    assert_rejected "${committed_name_repo}" "${fixture}/committed-${credential_name//./_}-output" \
        'release source contains forbidden generated/cache/backup/runtime path'

    dirty_name_repo="${fixture}/dirty-${credential_name//./_}"
    clone_boundary_repo "${dirty_name_repo}"
    mkdir -p -- "${dirty_name_repo}/neutral"
    chmod 0700 -- "${dirty_name_repo}/neutral" 2>/dev/null || true
    printf 'fixture-boundary-only\n' >"${dirty_name_repo}/neutral/${credential_name}"
    assert_rejected "${dirty_name_repo}" "${fixture}/dirty-${credential_name//./_}-output" \
        'dirty source contains forbidden transaction/credential/runtime path'
done

printf 'release source transaction and credential/runtime boundary tests: PASS\n'
