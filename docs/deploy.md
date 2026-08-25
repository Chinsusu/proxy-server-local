# Deploy PGW v2

## Trust bootstrap

Routine production lifecycle never runs Bash, Git, Go, or files from a caller
checkout as root. Release engineering runs `deploy/build-release.sh
--source-commit <full-SHA>` as an unprivileged account. It exports fresh Git
objects, downloads checksum-verified modules, switches networking off, runs
`go mod verify`, and performs two byte-identical builds. It produces:

- a static `CGO_ENABLED=0` `pgw-release-launcher`;
- a release tree containing prebuilt binaries and an exact allowlisted manifest;
- `release-trust.manifest`, which pins the release ID and manifest SHA-256.
- `source.manifest` plus the complete scanned source snapshot;
- `version.manifest`, recording source and Go target/toolchain while explicitly
  marking the result `candidate_only true`;
- `migration.manifest`, the contiguous embedded SQLite migration ledger;
- `build-proof.manifest` plus per-binary `go version -m`, `file` and `readelf`
  evidence proving `CGO_ENABLED=0` and no dynamic section.

A dirty tree may be assembled only with `--rehearsal-dirty`. Dirty and clean
local builds are equally nonpromotable. `GITHUB_*`, release IDs and local
manifests do not confer production authority.

Before canary, `deploy/rehearse-release.sh` runs only a capability-free non-root
filesystem fixture from a descriptor snapshot. It proves transaction logic but
explicitly records `production_root_lifecycle NOT_RUN` and `production_gate
FAIL`; this evidence cannot stand in for the separately signed protected-VM
full-system gate. It never deploys live.

`deploy/finalize-release.sh` descriptor-snapshots inputs before validation,
requires pinned Syft/Gitleaks, creates an SPDX JSON SBOM, exact six-binary
ledger, and separate empty scans for full source, candidate and ELF strings.
It revalidates staged bytes and emits `evidence.index` plus `SHA256SUMS`.
`--production` always fails closed. `deploy/close-release.sh` creates a
deterministic candidate tar.

Current repository CI creates a closed diagnostic candidate only. Every job
that executes repository/candidate code has `contents: read` only and receives
no OIDC, attestation permission, secret or authoritative key. Hosted-runner
sudo is not a trust boundary. Never promote the uploaded diagnostic artifact.

Production requires an independently pinned orchestrator outside this
repository trust domain. It may download the closed tar as data only and must
not checkout or execute candidate code. Its required identity, permissions,
custom candidate binding and deploy policy are defined in
`deploy/trust/external-attestor-handoff.json`. That contract is currently
`BLOCKED_UNPROVISIONED`, so production promotion/P0-09 remains unavailable.

After independent provisioning, the deploy host receives policy v2, pinned
attestor/`gh` binaries, a custom Sigstore trusted root and the fixed native entrypoint
under `/opt/pgw-release-trust`. Operators transport the exact `actions/attest`
bundle and candidate tar as root-owned files. The host uses no online
attestation API or PAT: the fixed native entrypoint verifies `--bundle` with the
pinned `--custom-trusted-root`, stages below `/var/lib/pgw/releases`, records a
receipt, and atomically replaces the runtime trust manifest. The checkout copy
is a reference only and cannot authorize promotion.

The entrypoint and attestor names are exactly two hardlinks to one reviewed
static binary. No shell is involved, so `BASH_ENV` is inert. Canonical bound
result JSON passes unchanged on stdout, stderr remains empty after verification, and exit codes
remain exactly `0`, `75`, `76`, or `77`. Only `0` is promoted; `76/77` require
manual state reconciliation before any retry or rollout. Earlier rejection
keeps stdout empty and its sanitized stderr/exit category.

The 12-file full-system raw evidence schema remains available to that external
orchestrator. Metadata/signature and raw file/aggregate bounds remain 4 KiB, 8
KiB, 16 KiB, 64 MiB/file, 256 MiB raw and 272 MiB evidence. Snapshot v2 also
preflights every file/directory, depth and aggregate path bytes before creating
an output tree; wide/deep inputs fail without partial materialization.

Image/package provisioning installs the launcher root-owned `0755`, the release
tree below `/var/lib/pgw/releases/<release-id>` with root ownership and no
group/world-writable ancestor, and the independently reviewed trust pin at
`/etc/pgw/release-trust.manifest` mode `0600`. This initial trust establishment is
an out-of-band packaging action, not an installer option. Never pin a manifest
from a checkout supplied by the operator running the update.

Before first install, provisioning also creates the independent random
`/etc/pgw/snapshot.hmac` (root `0600`, at least 32 bytes) and stages site
credentials at these fixed paths, each root-owned regular `0400`/`0600` file:

```text
/etc/pgw/credential-inbox/admin_password
/etc/pgw/credential-inbox/ui.crt
/etc/pgw/credential-inbox/ui.key
/etc/pgw/credential-inbox/ui_proxy_token
```

No source, toolchain, checkout, credential path, `BASH_ENV`, `ENV`, `LD_*`, or
test override is accepted from the caller. The launcher clears the entire
environment, validates every release ancestor and file descriptor, hashes the
opened descriptors, and passes only those same descriptors to the installer.

## Guarded install/update

Preserve OOB/console access. Validate that LAN `ens19` and WAN `eth0` are correct,
then run only:

```bash
sudo /usr/local/sbin/pgw-release-launcher --dry-run
sudo /usr/local/sbin/pgw-release-launcher
```

The installer requires exactly one global LAN IPv4 and binds UI HTTPS to that
address on port 8081. The immutable nft base allows management from the named LAN
and loopback, then explicitly drops management TCP from non-LAN IPv4 and all
IPv6. API remains numeric loopback. A wildcard management bind is invalid.

Install/update/rollback share `/run/pgw-lifecycle.lock`. Before mutation the
installer captures exact service/Forwarder states, SQLite/LKG/runtime, full nft
ruleset and `ip_forward`; authenticates the snapshot with the independent HMAC;
fsyncs every payload and directory; and writes a durable root-only recovery
journal. Restore publishes same-filesystem stages atomically. A crash with a
complete authenticated snapshot is resumed by restoring it before new work. A
capture failure before snapshot publication uses only the already-durable
service, Forwarder, ruleset and forwarding records to restore the exact pre-state;
the incomplete file tree is never treated as a rollback snapshot.
The saved forwarding value is captured first and then forced to `0` before any
service, nftables, firewall, or file mutation. Restore also begins at `0`,
restores and semantically verifies the exact saved ruleset, starts only the saved
services/Forwarders, and restores the prior forwarding value as the final step.
Any partial failure leaves forwarding at `0` and returns critical status `125`.
Snapshot metadata v3 lists only explicit, non-overlapping logical roots and
their descendants; staging scaffold directories are never restored or compared
to host parents. Each per-root restore operation is journaled with an identifier
derived from HMAC-authenticated metadata. Deterministic stage/tombstone residue
is therefore safe to finish after SIGKILL and is removed before forwarding can
be restored.

Metadata v3 authenticates fixed resource bounds with the snapshot: at most 4096
records, depth 32, 4096 bytes per logical path, 255 bytes per path member, 8 MiB
of aggregate path bytes, 512 KiB of aggregate member bytes, 16 GiB per regular
file, 64 GiB of aggregate regular-file data, 4096 bytes per symlink target, a
1 MiB manifest and 16 MiB metadata document.
Descriptor verification also caps retained descriptors at 4096 and preflights
the process `RLIMIT_NOFILE`, current descriptor use, and a 32-descriptor safety
reserve before recursion. Bound violations fail deterministically before the
snapshot checksum/HMAC and `ready` journal are published.

Rollback is deliberately schema-exact: this release accepts metadata v3 only.
A metadata-v2 snapshot must be restored with the originating, pinned release
launcher and artifacts; there is no privileged in-place v2-to-v3 migrator.
Capture uses one global manifest transaction and one aggregate budget across all
logical roots. A pre-ready `capturing` journal is independently authenticated;
state-only recovery is permitted only when neither ready checksum nor snapshot
HMAC exists. Once a complete seal exists, every failure remains a full-snapshot
recovery and cannot downgrade to state-only.

Rollback file contents are direct-to-ciphertext PGWSNAP objects: the backup has
an exact authenticated object manifest and no named plaintext tree. The
independently provisioned key ID has a durable per-key object-sequence ledger;
the installer preflights the helper's 1 GiB / `2^18` per-object limits and never
reuses an allocated sequence. Object-set, digest, helper metadata, and canonical
publication receipts are verified before checksum/HMAC publication.

Snapshot-helper exit `10` is an uncommitted failure. For exits `20` (commit
indeterminate), `21` (durability indeterminate), and `30` (durable commit but
acknowledgement failure), lifecycle code does not blindly retry. Ciphertext is
verified against the returned descriptor receipt; plaintext is reconciled by
descriptor-safe authenticated comparison with all expected metadata fields.
Any non-exact result retains the recovery journal and keeps forwarding off.
Restore first pre-verifies the entire ciphertext set, then creates an absent
root-owned `0700` stage under `/run/pgw`. Descriptor-safe, journaled atomic
host restore consumes that private stage; it is removed through pinned
descriptors after success or before a retry.

TLS certificate, key, and UI proxy token are copied from descriptor-validated
inbox files into a staged generation. The staged cert/key pair is verified before
an atomic `credentials-current` pointer is published. Source inbox files are
removed only after the new generation is durable.

## Verification

```bash
systemctl is-active nftables.service systemd-sysctl.service
systemctl is-active pgw-api.service pgw-agent.service pgw-ui.service pgw-health.service
sudo /usr/local/sbin/pgw-verify-base
curl --fail --cacert /etc/pgw/credentials-current/ui.crt \
  https://PGW_DNS_NAME:8081/login
sqlite3 /var/lib/pgw/pgw.db 'PRAGMA integrity_check;'
```

Validate control plane and data plane separately. From LAN, management login must
work over IPv4. LAN IPv6 and WAN IPv4/IPv6 access to TCP/8080 and TCP/8081 must
fail while a separate WAN control service remains reachable. Client canary traffic must exit only through
the configured proxy. Stopping Forwarder/API/Agent must never expose direct WAN.

## Rollback

```bash
sudo /usr/local/sbin/pgw-release-launcher \
  --rollback /var/backups/pgw/install.XXXXXXXX
```

Rollback accepts only a root-owned, non-writable, non-symlink snapshot directly
under `/var/backups/pgw`, with a valid HMAC. Any partial restore returns critical
status `125`, retains the recovery journal, and leaves services fail-closed.

Unsupported: root execution of repository shell scripts, caller-selected
checkout/commit/toolchain, Git pull/webhook update, manual binary/DB/UDS copying,
or nft/Forwarder control outside Agent.
