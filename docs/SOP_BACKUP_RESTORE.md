# SQLite backup and restore SOP

Production backup uses a consistent SQLite snapshot, SHA-256 manifest and
`PRAGMA integrity_check`. The transactional lifecycle must quiesce API, Agent,
UI, health and all Forwarders before restoring DB, UDS, LKG or runtime files.

Use `/usr/local/sbin/pgw-release-launcher --rollback <snapshot>`. It restores exact files,
ruleset, forwarding, enablement/activity and process binary identity. Manual
database copying or partial service restart is unsupported.

The rollback payload is publishable only after metadata-v3 resource bounds and
descriptor verification pass. The fixed contract limits the tree to 4096 nodes,
depth 32, 4096 bytes per path, 255 bytes per member, 8 MiB aggregate path bytes,
512 KiB aggregate member bytes, 16 GiB per file, 64 GiB aggregate file data, a
1 MiB manifest and a 16 MiB metadata document.
Verification reserves 32 file descriptors and rejects a tree that cannot fit
both the hard 4096-descriptor cap and the current `RLIMIT_NOFILE`. If capture
fails before checksum/HMAC publication, lifecycle recovery uses the durable
service/Forwarder/ruleset/forwarding records only; it never verifies or restores
the incomplete file payload.

Metadata v3 is not backward-migrated by a privileged installer. Restore a v2
snapshot only with its originating pinned release; otherwise keep forwarding
disabled and obtain the compatible artifact bundle. The authenticated recovery
journal also fixes the recovery mode durably: an unsealed `capturing` phase may
use state/runtime-only recovery, while `ready`, `restoring`, or a fully sealed
capture always require full snapshot recovery. A failed full recovery retains
the journal and deterministic restore residue, leaves application services
quiesced and keeps `ip_forward=0` with critical exit status 125.
# Encrypted rollback snapshots

Rollback snapshots are ciphertext-only PGWSNAP objects. Before any install or
rollback, an operator must independently provision `/etc/pgw/snapshot-encryption.key`
as a root-owned regular file with mode `0600` containing exactly 32 raw bytes.
The installer never generates, captures, exports, or rotates this key. A missing,
wrong, or altered key fails closed before host mutation. Rotate it only between
snapshot retention windows: retain the old key until every snapshot encrypted by
it is securely retired.

Each key file also has a root-only `/etc/pgw/snapshot-encryption.key.id` naming
the immutable key generation. The installer allocates a durable, monotonically
increasing object sequence beneath `/var/backups/pgw/key-sequences`; sequence
numbers are never reused after a failed capture. Do not delete that ledger while
any snapshot for the key ID is retained.

`pgw-snapshot-crypt` exit `10` means no object was committed. Exit `20` means
commit state is unknown, `21` means the link was observed but directory
durability is unknown, and `30` means a durable commit could not be
acknowledged. For `20`, `21`, and `30` the installer never retries publication:
it verifies the existing ciphertext receipt, or reconciles an existing
plaintext destination by authenticated byte-for-byte comparison. A missing or
mismatched receipt, key, ciphertext object, or metadata record leaves the
recovery journal in place with forwarding disabled.

Before a host restore, every ciphertext object, digest, object-set member and
receipt is verified. Decryption publishes only to a new root-owned `0700`
stage beneath `/run/pgw`; that stage is descriptor-cleaned on success or retry.
The backup itself contains no named plaintext. Per-root host replacement then
uses the metadata-checked atomic restore journal; forwarding is restored only
after every operation and final readback succeeds.
