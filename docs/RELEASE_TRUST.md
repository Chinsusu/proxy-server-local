# PGW release trust boundary

PGW has two distinct objects: a locally generated **candidate** and an
externally attested **release**. Files inside a candidate, including
`version.manifest`, never grant production authority. `GITHUB_*` environment
variables are deliberately ignored by the build and finalization scripts.

## Candidate construction

`deploy/build-release.sh --source-commit <full-SHA>` resolves an exact Git
commit and exports a fresh source tree from Git objects. A clean candidate is
never built from the caller's checkout. Its Go commands run with a cleared
environment, fixed `GOOS=linux`, `GOARCH=amd64`, `CGO_ENABLED=0`, `GOENV=off`,
`GOWORK=off`, a private module/build cache and an exact toolchain from `go.mod`.
Dependencies are downloaded under `go.sum`/SumDB control, `go mod verify` runs
in the same cache, and both builds run with `GOPROXY=off`. Every service and the
launcher is built twice and must be byte-identical.

The assembly contains the complete source snapshot and exact manifests for the
source, runtime release tree, migrations, six binaries and supporting ELF/Go
proof. `version.manifest` always contains:

```text
candidate_only true
promotion_authority external-github-attestation
```

`--rehearsal-dirty` is local diagnostic mode. It can never change those fields.

## Snapshot and evidence closure

`finalize-release.sh` first snapshots both input trees with descriptor-relative
opens and `O_NOFOLLOW`. Symlinks, FIFOs, devices, sockets, unsafe names,
concurrent replacement and changed directory membership fail closed. All
parsing, ELF validation, SBOM creation and secret scanning use only those staged
bytes. The staged trees are revalidated immediately before closure.

Snapshot v2 performs a descriptor-only preflight before creating the output:
every file and directory consumes the record, depth and aggregate path-byte
budgets. Default limits are 200,000 records, depth 64 and 32 MiB path bytes;
evidence limits are 256 records, depth 8 and 64 KiB path bytes. Wide/deep empty
trees therefore fail without partial materialization.

Manifest parsers reject duplicate, missing, extra, malformed and traversing
records. Syft and Gitleaks binaries and embedded module versions are pinned.
The evidence contains:

- an SPDX 2.3 SBOM and an exact six-binary subject ledger;
- separate empty Gitleaks reports for the full source snapshot, the candidate,
  and strings extracted from all six ELF binaries;
- raw ELF digests, string-input digests, tool versions and scanner digests;
- immutable assembly/rehearsal snapshot manifests;
- `evidence.index` and verified `SHA256SUMS`.

`finalize-release.sh --production` is intentionally unsupported. The output is
still nonpromotable. `close-release.sh` snapshots that output again and creates
two deterministic tar files; a byte mismatch fails the build.
`promotion.manifest` v2 explicitly records `production_promotion_available
false` and requires an independent external signer/policy.

## Full-system and production authority

The repository rehearsal emits non-root fixture evidence only. It cannot claim
that production root lifecycle ran. The current CI closes and uploads a
diagnostic candidate only. Every job that checks out or executes candidate code
has exactly `contents: read`, no OIDC/attestation permission, no secret and no
authoritative key. Passwordless sudo on a hosted runner is explicitly not a
privilege boundary. This repository cannot self-attest a production release.

The exact 12-file raw evidence schema and signature-first bounded parser remain
the consumption contract for a future external orchestrator: manifest 4 KiB,
index 8 KiB, signature 16 KiB, 64 MiB per raw file, 256 MiB raw total and 272
MiB evidence total. However no current workflow provisions or consumes
authoritative full-system key material.

Production requires an independently pinned orchestrator outside the candidate
repository/SHA. It may download the closed candidate only as data and must not
checkout or execute candidate code. The machine-readable handoff at
`deploy/trust/external-attestor-handoff.json` is intentionally
`BLOCKED_UNPROVISIONED`; therefore production promotion/P0-09 is unavailable.

The external signer must upload the exact offline Sigstore bundle returned by
`actions/attest`. Before promotion, independent operators install root-owned,
digest-pinned attestor/`gh` binaries, custom Sigstore trusted root and strict
policy outside the checkout. The policy pins exact signer and evidence producer
repository/workflow/ref/SHA/run-attempt identities, the evidence DER-SPKI key
SHA-256, verifier build metadata, predicate type, certificate identity/issuer,
and all executable/trusted-root digests.

The PGW host accepts only the transported candidate and bundle. It performs no
online attestation lookup and receives no PAT. The installed native entrypoint
is a second hardlink to the exact attestor binary and accepts only two absolute
positional paths. The promoter verifies using `--bundle`, a root-owned pinned
`--custom-trusted-root`, and `--no-public-good`; it then stages the release,
writes a durable receipt and atomically replaces the runtime trust manifest.
A print-only verifier result, candidate workflow, GitHub run ID, local checksum
or candidate manifest is never promotion authority.

No shell or output intermediary runs, so hostile `BASH_ENV` cannot execute
before native verification. After a verified attempt the binary byte-preserves
canonical `pgw-promotion-result-v1` JSON on stdout,
keeps stderr empty, and returns `0` (promoted), `75` (pre-commit failed), `76`
(commit indeterminate), or `77` (committed durability indeterminate). The JSON
retains release, candidate, bundle and predicate bindings for reconciliation,
but only exit `0` is success. Stop automated rollout on `76` or `77`.
Pre-verification rejection retains empty stdout and sanitized stderr.
Caller-controlled `argv[0]` is untrusted. The kernel `AT_EXECFN` value read via
bounded `/proc/self/auxv` and `/proc/self/mem` must exactly equal the fixed clean
absolute entrypoint path. That fixed entrypoint, trusted attestor path and
`/proc/self/exe` must also be the same root-owned `0555` regular inode with link
count exactly two. `exec -a` spoofing, relative, symlink, proc-fd/execveat,
copied, wrong-alias and extra-hardlink execution are rejected.

The signer certificate and candidate predicate have separate event contracts:
the environment-approved signer must have GitHub trigger `workflow_dispatch`,
while the candidate predicate must retain `event=push`. The verifier checks both
and does not accept either value in the other's position.

The runtime launcher trust manifest remains an exact pin:

```text
format pgw-trust-v1
release_id <safe-id>
manifest_sha256 <64 lowercase hexadecimal characters>
```

Only the independently installed promoter may replace that pin after successful
offline verification and atomic staging. The routine installer never writes or
rotates its own launcher or trust root.
