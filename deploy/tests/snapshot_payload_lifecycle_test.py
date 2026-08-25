#!/usr/bin/env python3
"""Portable fault contracts for the encrypted snapshot wrapper.

The Go helper has Linux-root tests for O_TMPFILE/link faults. These tests keep
the installer-side policy deterministic on any developer platform: unstable
publication exits reconcile once with all descriptor-bound expectations and
never trigger a blind publication retry.
"""

from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import tempfile
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("snapshot_payload_under_test", ROOT / "deploy/snapshot_payload.py")
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def metadata() -> dict[str, object]:
    return {
        "format_version": 2,
        "snapshot_id": "install.fixture",
        "release_id": "release.fixture",
        "key_id": "key.fixture",
        "key_object_sequence": 7,
        "logical_path": "/var/lib/pgw/pgw.db",
        "uid": 0,
        "gid": 0,
        "mode": 0o600,
        "source_device": 11,
        "source_inode": 12,
        "plaintext_length": 4,
        "source_mtime_ns": 13,
        "source_ctime_ns": 14,
        "chunk_size": MODULE.CHUNK_SIZE,
    }


def receipt() -> dict[str, object]:
    return {
        "final_identity_known": True,
        "final_device": 21,
        "final_inode": 22,
        "final_size": 23,
        "final_uid": 0,
        "final_gid": 0,
        "final_mode": 0o600,
    }


def success(status: str, destination_field: str, destination: str) -> dict[str, object]:
    return {"status": status, **metadata(), destination_field: destination, **receipt()}


def failure(code: int, operation: str, destination: str, action: str, known: bool) -> dict[str, object]:
    outcomes = {
        10: "pre_commit_failure",
        20: "commit_indeterminate",
        21: "durability_indeterminate",
        30: "durable_committed_ack_failure",
    }
    value = {
        "status": "error", "outcome": outcomes[code], "exit_code": code,
        "operation": operation, "reconcile_action": action,
        "final_identity_known": known,
        "final_device": 21 if known else 0,
        "final_inode": 22 if known else 0,
        "final_size": 23 if known else 0,
        "final_uid": 0, "final_gid": 0, "final_mode": 0o600 if known else 0,
    }
    if code != 10:
        value["destination"] = destination
    return value


def run_encrypt_fault(code: int) -> None:
    calls: list[list[str]] = []
    output = "/backup/objects/object.pgwsnap"

    def fake_run(command: list[str], context: str):
        calls.append(command)
        if command[1] == "encrypt":
            return code, failure(code, "encrypt", output, "none" if code == 10 else "verify-existing-ciphertext", code in (21, 30))
        assert command[1] == "verify"
        if code in (21, 30):
            assert command.count("--expect-final-device") == 1
            assert command[command.index("--expect-final-device") + 1] == "21"
            assert command[command.index("--expect-final-inode") + 1] == "22"
        else:
            assert "--expect-final-device" not in command
        return 0, success("verified", "input", output)

    with mock.patch.object(MODULE, "_run", side_effect=fake_run):
        if code == 10:
            try:
                MODULE.encrypt_object("helper", "/key", "key.fixture", "/source", output, metadata())
            except SystemExit as error:
                assert str(error) == "snapshot encryption failed before commit"
            else:
                raise AssertionError("pre-commit encryption failure was accepted")
        else:
            assert MODULE.encrypt_object("helper", "/key", "key.fixture", "/source", output, metadata()) == receipt()
    assert [call[1] for call in calls] == (["encrypt"] if code == 10 else ["encrypt", "verify"])


def run_decrypt_fault(code: int) -> None:
    calls: list[list[str]] = []
    destination = "/run/pgw/stage/files/var/lib/pgw/pgw.db"

    def fake_run(command: list[str], context: str):
        calls.append(command)
        if command[1] == "decrypt-publish":
            action = "none" if code == 10 else "reconcile-publish"
            return code, failure(code, "decrypt-publish", destination, action, code in (21, 30))
        assert command[1] == "reconcile-publish"
        for flag in MODULE._expected_arguments(metadata())[::2]:
            assert flag in command, flag
        return 0, success("reconciled", "destination", destination)

    with mock.patch.object(MODULE, "_run", side_effect=fake_run):
        if code == 10:
            try:
                MODULE.decrypt_publish("helper", "/key", "/cipher", destination, metadata())
            except SystemExit as error:
                assert str(error) == "snapshot plaintext publication failed before commit"
            else:
                raise AssertionError("pre-commit plaintext failure was accepted")
        else:
            assert MODULE.decrypt_publish("helper", "/key", "/cipher", destination, metadata()) == receipt()
    assert [call[1] for call in calls] == (["decrypt-publish"] if code == 10 else ["decrypt-publish", "reconcile-publish"])


for exit_code in (10, 20, 21, 30):
    run_encrypt_fault(exit_code)
    run_decrypt_fault(exit_code)

# A failed preverification must prevent even creation of a private plaintext
# stage. This covers missing/wrong keys, ciphertext tamper/truncation and an
# extra/missing object because they all fail the same full verify gate.
with mock.patch.object(MODULE, "verify", side_effect=SystemExit("wrong key")), \
     mock.patch.object(MODULE, "create_private_stage") as stage:
    try:
        MODULE.materialize("/snapshot", "/missing-or-wrong-key", "helper", "/run/pgw/stage")
    except SystemExit as error:
        assert str(error) == "wrong key"
    else:
        raise AssertionError("materialize accepted an unverified ciphertext set")
    stage.assert_not_called()

if os.name == "posix":
    with tempfile.TemporaryDirectory() as temporary:
        files = pathlib.Path(temporary) / "files"
        files.mkdir(mode=0o700)
        parent = MODULE.ensure_private_restore_parent(
            str(files), "/usr/local/bin/pgw-api",
        )
        assert pathlib.Path(parent) == files / "usr/local/bin"
        for scaffold in (files / "usr", files / "usr/local", files / "usr/local/bin"):
            assert scaffold.is_dir() and not scaffold.is_symlink()
            assert scaffold.stat().st_mode & 0o7777 == 0o700
        outside = pathlib.Path(temporary) / "outside"
        outside.mkdir(mode=0o700)
        hostile = files / "etc"
        hostile.symlink_to(outside, target_is_directory=True)
        try:
            MODULE.ensure_private_restore_parent(str(files), "/etc/pgw/secret")
        except SystemExit as error:
            assert str(error) == "unsafe restore parent"
        else:
            raise AssertionError("symlinked restore scaffold was accepted")

# Key sequence allocation is durable and monotonic. The manifest validator
# independently rejects reuse so a damaged ledger cannot produce a valid seal.
with tempfile.TemporaryDirectory() as temporary:
    root = pathlib.Path(temporary)
    ledger_dir = root / "key-sequences"
    ledger_dir.mkdir(mode=0o700)
    ledger = ledger_dir / ("key-sequence-" + MODULE.hashlib.sha256(b"key.fixture").hexdigest() + ".json")
    assert MODULE.allocate_sequences(str(ledger), "key.fixture", 2) == 0
    assert MODULE.allocate_sequences(str(ledger), "key.fixture", 3) == 2
    assert json.loads(ledger.read_text(encoding="utf-8"))["next_sequence"] == 5

entries = [("present", "/var/lib/pgw")]
first = {"logical_path": "/var/lib/pgw", "kind": "directory", "uid": 0, "gid": 0, "mode": 0o700}
second = {
    "logical_path": "/var/lib/pgw/a", "kind": "regular", **metadata(),
    "object": MODULE.object_name("/var/lib/pgw/a"), "cipher_sha256": "0" * 64,
    "ciphertext_receipt": receipt(),
}
second["logical_path"] = "/var/lib/pgw/a"
third = dict(second)
third["logical_path"] = "/var/lib/pgw/b"
third["object"] = MODULE.object_name("/var/lib/pgw/b")
try:
    MODULE._validate_payload_records([first, second, third], entries, "key.fixture")
except SystemExit as error:
    assert str(error) == "duplicate key object sequence"
else:
    raise AssertionError("reused key sequence was accepted")


def make_payload_fixture(root: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
    snapshot = root / "snapshot"
    objects = snapshot / "objects"
    objects.mkdir(parents=True)
    (snapshot / "manifest").write_text("present\t/var/lib/pgw\n", encoding="utf-8")
    cipher = objects / MODULE.object_name("/var/lib/pgw/a")
    cipher.write_bytes(b"ciphertext-canary")
    item = {
        "logical_path": "/var/lib/pgw/a", "kind": "regular", **metadata(),
        "object": cipher.name, "cipher_sha256": MODULE.digest(str(cipher)),
        "ciphertext_receipt": receipt(),
    }
    item["logical_path"] = "/var/lib/pgw/a"
    (snapshot / "payload.manifest.json").write_text(json.dumps({
        "format": "pgw-encrypted-snapshot-v2", "snapshot_id": "install.fixture",
        "release_id": "release.fixture", "key_id": "key.fixture",
        "records": [first, item],
    }, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    return snapshot, cipher


def expect_verify_failure(label: str, action, expected: str) -> None:
    try:
        action()
    except SystemExit as error:
        assert str(error) == expected, (label, str(error))
    else:
        raise AssertionError(label + " unexpectedly verified")


with tempfile.TemporaryDirectory() as temporary:
    root = pathlib.Path(temporary)
    snapshot, cipher = make_payload_fixture(root)
    with mock.patch.object(MODULE, "_verify_ciphertext", return_value=({}, receipt())):
        MODULE.verify(str(snapshot), "/key", "helper")
    cipher.write_bytes(b"truncated")
    expect_verify_failure("truncate", lambda: MODULE.verify(str(snapshot), "/key", "helper"), "ciphertext digest mismatch")
    cipher.write_bytes(b"ciphertext-canary-tampered")
    expect_verify_failure("tamper", lambda: MODULE.verify(str(snapshot), "/key", "helper"), "ciphertext digest mismatch")
    cipher.unlink()
    expect_verify_failure("missing", lambda: MODULE.verify(str(snapshot), "/key", "helper"), "ciphertext object is missing or unreadable")

with tempfile.TemporaryDirectory() as temporary:
    root = pathlib.Path(temporary)
    snapshot, _ = make_payload_fixture(root)
    (snapshot / "objects" / "extra.pgwsnap").write_bytes(b"extra")
    with mock.patch.object(MODULE, "_verify_ciphertext", return_value=({}, receipt())):
        expect_verify_failure("extra", lambda: MODULE.verify(str(snapshot), "/key", "helper"), "encrypted payload object set mismatch")

with tempfile.TemporaryDirectory() as temporary:
    root = pathlib.Path(temporary)
    snapshot, _ = make_payload_fixture(root)
    with mock.patch.object(MODULE, "_verify_ciphertext", side_effect=SystemExit("wrong or missing key")):
        expect_verify_failure("wrong-key", lambda: MODULE.verify(str(snapshot), "/key", "helper"), "wrong or missing key")

payload_source = (ROOT / "deploy/snapshot_payload.py").read_text(encoding="utf-8")
assert "reconcile-publish" in payload_source
assert "snapshot regular object exceeds 1 GiB preflight" in payload_source
assert "snapshot regular object exceeds 2^18 chunk preflight" in payload_source
assert "create_private_stage(destination)" in payload_source
assert '"${backup_dir}/files/' not in (ROOT / "deploy/install-pgw.sh").read_text(encoding="utf-8")

print("snapshot payload lifecycle contracts: PASS")
