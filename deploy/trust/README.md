# Protected offline release trust bootstrap

Production promotion is an offline, root-owned transaction. An independent
bootstrap process—not candidate CI—must install:

```text
/opt/pgw-release-trust/bin/attestor                     root:root 0555
/opt/pgw-release-trust/bin/gh                           root:root 0555
/opt/pgw-release-trust/bin/verify-release-attestation   root:root 0555 (hardlink to attestor)
/opt/pgw-release-trust/external-attestor.policy         root:root 0444
/opt/pgw-release-trust/sigstore-trusted-root.json       root:root 0444
```

`attestor` and `verify-release-attestation` are the exact two hardlinks to one
reviewed static attestor asset: same device/inode, link count exactly two, no
symlink and no copied launcher. The candidate repository ships no executable
trust entrypoint. During a maintenance freeze, stage a new two-link pair on the
same filesystem, verify the bootstrap digest/build metadata, then rename
`attestor` first and `verify-release-attestation` second. Each rename is atomic;
the transient mismatch fails closed. Fsync the directory after staging and each
rename. Never create a shell wrapper or a second independently built asset.

Run the reviewed ceremony from a clean privileged maintenance environment. The
following is an apply-later command shape, not an action performed by CI:

```bash
sudo env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin /bin/bash --noprofile --norc <<'CEREMONY'
set -euo pipefail
trust_bin=/opt/pgw-release-trust/bin
approved_asset=/var/lib/pgw/bootstrap-inbox/attestor-linux-amd64
expected_sha=BLOCKED_UNPROVISIONED
expected_version=BLOCKED_UNPROVISIONED
expected_commit=BLOCKED_UNPROVISIONED
expected_source_sha=BLOCKED_UNPROVISIONED
[[ "$expected_sha" =~ ^[0-9a-f]{64}$ && "$expected_version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ &&
   "$expected_commit" =~ ^[0-9a-f]{40}$ &&
   "$expected_source_sha" =~ ^[0-9a-f]{64}$ ]]
[[ ! -e "$trust_bin/.attestor.next" && ! -e "$trust_bin/.verify.next" ]]
stage="$(mktemp -d "$trust_bin/.native-pair.XXXXXX")"
install -o root -g root -m 0555 "$approved_asset" "$stage/attestor"
[[ "$(sha256sum "$stage/attestor" | awk '{print $1}')" == "$expected_sha" ]]
metadata="$("$stage/attestor" version)"
jq -e --arg version "$expected_version" --arg commit "$expected_commit" \
  --arg source "$expected_source_sha" \
  '.name == "trusted-release-attestor" and .version == $version and
   .commit == $commit and .source_digest == $source' <<<"$metadata" >/dev/null
ln "$stage/attestor" "$stage/verify-release-attestation"
[[ "$(stat -Lc '%d:%i:%h' "$stage/attestor")" == \
   "$(stat -Lc '%d:%i:%h' "$stage/verify-release-attestation")" ]]
mv -T "$stage/attestor" "$trust_bin/.attestor.next"
mv -T "$stage/verify-release-attestation" "$trust_bin/.verify.next"
rmdir "$stage"
sync -f "$trust_bin"
mv -T "$trust_bin/.attestor.next" "$trust_bin/attestor"
sync -f "$trust_bin"
mv -T "$trust_bin/.verify.next" "$trust_bin/verify-release-attestation"
sync -f "$trust_bin"
CEREMONY
```

Before the first rename, verify the staged `attestor` using the reviewed
bootstrap asset verifier and recorded digest/version/commit/source digest.
After the second rename, run the read-only native-install verifier from the same
reviewed attestor source. Retain both results and the final inode/link-count
`stat` output. If interrupted between fixed-path renames, promotion remains
unavailable until the reviewed pair is completed or restored.

Provision the runtime lock boundary at every boot with a reviewed, root-owned
tmpfiles configuration:

```text
d /run/pgw-release-trust 0755 root root -
f /run/pgw-release-trust/promotion.lock 0600 root root -
```

The parent may instead be `0700` or `0750`, but it must be root-owned and not
group/world-writable. The lock must be an empty, single-link, root-owned regular
file at mode `0600`; the root attestor may create it if absent. Never repurpose
or chmod the system `/run/lock`. Before promotion, record
`stat -Lc '%U:%G %a %F %s %h %n'` for the parent and lock plus tmpfiles/boot
evidence; the promoter independently enforces this contract.

The strict `pgw-external-attestor-policy-v2` pins the attestor and `gh` binary
SHA-256 values, custom Sigstore trusted-root SHA-256, signer certificate and
workflow identity, predicate type, verifier build metadata, evidence producer
repository/workflow/ref/SHA/run-attempt, and evidence DER-SPKI public-key
SHA-256. The evidence repository must differ from both the candidate and
attestor repositories. The predicate type URL remains `external-release/v1`,
while the predicate object must use schema
`pgw-external-release-attestation-predicate-v2`. Until every component exists
and the machine-readable `pgw-external-attestor-handoff-v6` handoff remains
`BLOCKED_UNPROVISIONED`, production promotion is unavailable.

The external signer uploads the exact bundle returned by `actions/attest`.
Operators transport that bundle and the closed candidate tar to root-owned
regular non-symlink files with no write bits (`0400`, `0440` or `0444`) on the
PGW host. No GitHub token, PAT, online attestation API or
public-good lookup is allowed on the host. The promoter runs fixed, digest-
pinned `gh attestation verify` with `--bundle`, `--custom-trusted-root` and
`--no-public-good` under an empty environment.

Invoke only the independently installed native entrypoint with two clean
absolute positional paths:

```bash
/opt/pgw-release-trust/bin/verify-release-attestation \
  /var/lib/pgw/promotion-inbox/pgw-release-candidate.tar \
  /var/lib/pgw/promotion-inbox/attestation.bundle.jsonl
```

`argv[0]` is untrusted caller input and never authorizes promotion. The binary
requires the kernel `AT_EXECFN` value read from bounded `/proc/self/auxv` and
`/proc/self/mem` to be the exact clean absolute fixed entrypoint path. It then
proves `/proc/self/exe`, the entrypoint and `attestor` are the same root-owned
`0555` regular inode with exactly two links. `exec -a` spoofing, relative,
symlink, `/proc/self/fd`/`execveat`, copied and wrong-alias execution, malformed
auxv, and extra hardlinks fail. It then rechecks all
policy, input, candidate, certificate, predicate and evidence bindings; stages
below `/var/lib/pgw/releases`; writes a durable receipt below
`/var/lib/pgw/promotion-receipts`; and atomically replaces
`/etc/pgw/release-trust.manifest`. A printed verification message alone is not
promotion. Checkout files and locally built binaries have no authority.

There is no shell interpreter or output intermediary, so `BASH_ENV` has no
pre-interpreter surface and callers receive the exact canonical
`pgw-promotion-result-v1` JSON bytes and exact authoritative exit code:

- `0` / `promoted`: the promotion committed successfully;
- `75` / `pre_commit_failed`: no promotion commit was reported;
- `76` / `commit_indeterminate`: the commit point is ambiguous;
- `77` / `committed_durability_indeterminate`: commit occurred or may have
  occurred, but its durability could not be established.

All four post-verification outcomes retain release ID plus release-manifest,
candidate, offline-bundle, and predicate SHA-256 bindings on stdout, with empty
stderr. Automation must persist that stdout byte-for-byte and branch on the
exit code; it must stop and reconcile on `76` or `77`, never infer success from
JSON presence alone. Native entrypoint/promoter failures before a verified outcome keep
stdout empty and use their existing sanitized stderr and exit categories.

The signer certificate trigger is exactly `workflow_dispatch`; the predicate's
candidate event is independently exactly `push`. The evidence predicate binds
the v2 index/v3 signed manifest provenance fields. Swapped triggers, an online
bundle lookup, a different evidence producer revision/attempt/key, and any
candidate-provided policy fail closed.
