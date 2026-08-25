#!/usr/bin/python3
"""Portable structural contracts for encrypted snapshot staging.

Linux/root fault injection remains a separate CI gate; this test guards the
properties that must not regress on a developer host.
"""
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
payload=(ROOT/"deploy/snapshot_payload.py").read_text(encoding="utf-8")
installer=(ROOT/"deploy/install-pgw.sh").read_text(encoding="utf-8")

required=(
    '"format": "pgw-encrypted-snapshot-v2"',
    'key_object_sequence',
    'ciphertext digest mismatch',
    'verify(snapshot, key, helper)',
    'decrypt-publish',
    'expect-key-object-sequence',
    'expect-inode',
    'expect-ctime-ns',
    'PUBLICATION_EXITS',
    'reconcile-publish',
    'canonical_receipt',
    'create_private_stage(destination)',
    'snapshot regular object exceeds 1 GiB preflight',
    'snapshot regular object exceeds 2^18 chunk preflight',
    'create_private_stage(destination)',
    'remove_private_stage',
    'remove_legacy_report_runtime',
    'remove-legacy-report',
)
for value in required:
    assert value in payload, value
assert '"--source-contract", "quiesced"' in payload
assert 'temporary_path' not in payload
assert '"${backup_dir}/files/' not in installer
assert 'verify_snapshot payload || return 1' in installer
assert 'verify_snapshot_payload || die "rollback ciphertext payload self-check failed"' in installer
assert 'materialize' in installer
assert 'write_restore_progress' in installer
assert 'remove_snapshot_stage' in installer
assert 'key-sequence-' in installer
print("encrypted snapshot portable contracts: PASS")
