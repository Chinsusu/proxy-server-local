// Package snapshotcrypto implements the PGW v2 per-file rollback ciphertext
// format and Linux descriptor-pinned publication primitives.
//
// The fixed header is "PGWSNAP\x00", version u16, field count u16, and TLV-byte
// length u32. It is followed by exactly fifteen canonical, ascending TLVs:
// snapshot ID, release ID, nonsecret key ID, key-object sequence, logical path, uid, gid, mode,
// source device, source inode, plaintext length, source mtime_ns, source
// ctime_ns, chunk size, and a fresh 16-byte salt. All integers are unsigned
// big-endian except timestamps, whose signed int64 bit patterns are encoded as
// u64. Unknown, missing, duplicate, reordered, or noncanonical fields fail.
//
// AES-256-GCM object keys are HKDF-SHA-256(master, salt,
// "PGW-SNAPSHOT-OBJECT-KEY-V2\x00" || complete-header). The deterministic
// 96-bit nonce is "PGW\x02" || counter-u64. Each record is counter u64, final
// byte, ciphertext length u32, and ciphertext. AAD is
// "PGW-SNAPSHOT-CHUNK-AAD-V2\x00" || complete-header || counter-u64 || final.
// Counters start at zero and are strict. Empty objects have one final record.
//
// A derived object key is limited to 1 GiB and MaxChunksPerObject (2^18)
// records, whichever is reached first. This conservative cap bounds aggregate
// GCM forgery exposure even though the full canonical header is repeated as
// AAD for every record. The authenticated
// key-object sequence must be below MaxObjectsPerKeyID, forcing a new key ID and
// master key generation before that bound. Installers additionally enforce
// uniqueness against the authenticated manifest. The key
// ID is authenticated and must uniquely identify one immutable master-key
// generation; reassigning an old key ID to different bytes is prohibited.
//
// Decrypt-publish requires an absent destination. It writes only to O_TMPFILE,
// compares every authenticated field with an independently authenticated
// expected manifest record, applies ownership/mode, fsyncs, then links the
// unnamed inode directly to the final descriptor-relative basename and fsyncs
// the pinned parent. There is no named plaintext staging state for SIGKILL to
// strand. Multi-file completeness remains the authenticated manifest's job.
// Encryption likewise stages ciphertext in O_TMPFILE, fsyncs it, links it
// directly to an absent final basename, and fsyncs the pinned parent.
//
// The CLI fails closed unless Linux process hardening succeeds: umask 0077,
// RLIMIT_CORE zero, PR_SET_DUMPABLE zero, and PR_SET_NO_NEW_PRIVS. Operators
// must additionally use a private service account boundary, sanitized
// environment, closed inherited descriptors, memory/swap controls appropriate
// for key material, and a quiesced source. Exit codes are stable: 10 means no
// commit, 20 commit state unknown, 21 link observed but directory durability
// unknown, and 30 durably committed but acknowledgement/close/output failed.
// Codes 20, 21, and 30 prohibit blind retry. Encrypt reconciliation runs
// verify with the returned expected device/inode receipt; plaintext
// reconciliation runs reconcile-publish, which re-authenticates ciphertext
// and compares the existing destination byte-for-byte through pinned
// descriptors without emitting a plaintext digest. A successful
// reconciliation also fsyncs the exact opened final inode and its retained,
// trusted parent directory, then descriptor-relatively revalidates the final
// basename's type, device, inode, and metadata. Sync or revalidation failure is
// durability-indeterminate (exit 21), never a successful reconciliation.
package snapshotcrypto
