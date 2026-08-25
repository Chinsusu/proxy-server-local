#!/usr/bin/python3
"""Ciphertext-only PGW rollback-payload lifecycle.

The installer never writes a plaintext backup. A quiesced host object is
encrypted directly into an absent PGWSNAP object and the only plaintext used
for rollback is published into a private, root-owned ``/run/pgw`` stage. The
snapshot helper has explicit publication outcomes; an uncertain commit is
reconciled exactly once against its canonical receipt, never retried.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import posixpath
import re
import stat
import subprocess
import sys
from typing import Any


MAX_MANIFEST_BYTES = 1024 * 1024
MAX_RECORDS = 4096
MAX_PLAINTEXT_BYTES = 1 << 30
MAX_CHUNKS_PER_OBJECT = 1 << 18
CHUNK_SIZE = 1024 * 1024
MAX_OBJECT_SEQUENCE = 1 << 32
ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
HEX_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
PUBLICATION_EXITS = {
    10: ("pre_commit_failure", "none"),
    20: ("commit_indeterminate", "verify-existing-ciphertext"),
    21: ("durability_indeterminate", "verify-existing-ciphertext"),
    30: ("durable_committed_ack_failure", "verify-existing-ciphertext"),
}

METADATA_FIELDS = (
    "format_version", "snapshot_id", "release_id", "key_id",
    "key_object_sequence", "logical_path", "uid", "gid", "mode",
    "source_device", "source_inode", "plaintext_length", "source_mtime_ns",
    "source_ctime_ns", "chunk_size",
)
RECEIPT_FIELDS = (
    "final_identity_known", "final_device", "final_inode", "final_size",
    "final_uid", "final_gid", "final_mode",
)
O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)


def die(message: str) -> None:
    raise SystemExit(message)


def canonical(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith("/")
        or value == "/"
        or posixpath.normpath(value) != value
        or "\x00" in value
        or "\\" in value
    ):
        die("unsafe logical path")
    return value


def identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or ID_PATTERN.fullmatch(value) is None:
        die("invalid " + field)
    return value


def _source_identity(info: os.stat_result) -> tuple[int, int, int, int, int, int, int, int, int]:
    return (
        info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode), stat.S_IMODE(info.st_mode),
        info.st_uid, info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
    )


def digest(path: str) -> str:
    result = hashlib.sha256()
    descriptor = os.open(path, os.O_RDONLY | O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            die("snapshot object is not a regular file")
        while True:
            block = os.read(descriptor, 1 << 20)
            if not block:
                break
            result.update(block)
        if _source_identity(os.fstat(descriptor)) != _source_identity(info):
            die("snapshot object changed while hashing")
    finally:
        os.close(descriptor)
    return result.hexdigest()


def object_name(logical: str) -> str:
    return hashlib.sha256(logical.encode("utf-8")).hexdigest() + ".pgwsnap"


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            die("short snapshot metadata write")
        view = view[written:]


def _json_line(payload: str, context: str) -> dict[str, Any]:
    if payload.count("\n") != 1 or not payload.endswith("\n"):
        die(context + " returned non-canonical result")
    try:
        decoded = json.loads(payload)
    except ValueError:
        die(context + " returned invalid result")
    if not isinstance(decoded, dict):
        die(context + " returned invalid result")
    return decoded


def _run(command: list[str], context: str) -> tuple[int, dict[str, Any]]:
    result = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    return result.returncode, _json_line(result.stdout, context)


def _integer(value: Any, field: str, *, signed: bool = False) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        die("invalid helper " + field)
    if not signed and value < 0:
        die("invalid helper " + field)
    if signed and not -(1 << 63) <= value < (1 << 63):
        die("invalid helper " + field)
    return value


def canonical_receipt(result: dict[str, Any], destination: str) -> dict[str, Any]:
    required = set(RECEIPT_FIELDS)
    if not required.issubset(result):
        die("helper omitted publication receipt")
    if result["final_identity_known"] is not True:
        die("helper returned an indeterminate publication receipt")
    receipt = {field: result[field] for field in RECEIPT_FIELDS}
    for field in RECEIPT_FIELDS[1:]:
        _integer(receipt[field], field)
    if receipt["final_device"] == 0 or receipt["final_inode"] == 0:
        die("helper returned an invalid publication receipt")
    if receipt["final_mode"] > 0o7777:
        die("helper returned an invalid publication receipt")
    emitted = result.get("destination", result.get("output", result.get("input")))
    if emitted != destination:
        die("helper receipt destination mismatch")
    return receipt


def canonical_failure(
    result: dict[str, Any], exit_code: int, operation: str, destination: str,
    reconcile_action: str,
) -> dict[str, Any]:
    expected_outcome, default_action = PUBLICATION_EXITS[exit_code]
    expected_action = "reconcile-publish" if operation == "decrypt-publish" and exit_code != 10 else default_action
    if reconcile_action != expected_action:
        die("internal publication reconciliation policy mismatch")
    required = {
        "status", "outcome", "exit_code", "operation", "reconcile_action",
        *RECEIPT_FIELDS,
    }
    allowed = required | {"destination"}
    if set(result) - allowed or not required.issubset(result):
        die("helper returned non-canonical publication failure")
    if (
        result["status"] != "error"
        or result["outcome"] != expected_outcome
        or result["exit_code"] != exit_code
        or result["operation"] != operation
        or result["reconcile_action"] != reconcile_action
    ):
        die("helper publication failure classification mismatch")
    if exit_code == 10:
        if result.get("destination", "") not in ("", destination):
            die("helper pre-commit destination mismatch")
        return {}
    if result.get("destination") != destination:
        die("helper uncertain publication destination mismatch")
    known = result.get("final_identity_known")
    if not isinstance(known, bool):
        die("helper returned invalid receipt identity flag")
    receipt = {field: result[field] for field in RECEIPT_FIELDS}
    for field in RECEIPT_FIELDS[1:]:
        _integer(receipt[field], field)
    if exit_code in (21, 30) and known is not True:
        die("helper omitted linked publication receipt")
    if known and (receipt["final_device"] == 0 or receipt["final_inode"] == 0):
        die("helper returned invalid linked publication receipt")
    return receipt


def _metadata_from_result(result: dict[str, Any]) -> dict[str, Any]:
    if set(METADATA_FIELDS) - set(result):
        die("helper omitted authenticated metadata")
    metadata = {field: result[field] for field in METADATA_FIELDS}
    if metadata["format_version"] != 2:
        die("helper emitted unsupported snapshot format")
    for field in ("snapshot_id", "release_id", "key_id"):
        identifier(metadata[field], field)
    canonical(metadata["logical_path"])
    for field in (
        "key_object_sequence", "uid", "gid", "mode", "source_device",
        "source_inode", "plaintext_length", "chunk_size",
    ):
        _integer(metadata[field], field)
    for field in ("source_mtime_ns", "source_ctime_ns"):
        _integer(metadata[field], field, signed=True)
    if metadata["mode"] > 0o7777:
        die("invalid helper mode")
    if metadata["key_object_sequence"] >= MAX_OBJECT_SEQUENCE:
        die("helper key object sequence exceeds rotation limit")
    if metadata["plaintext_length"] > MAX_PLAINTEXT_BYTES:
        die("helper plaintext exceeds 1 GiB limit")
    if metadata["chunk_size"] <= 0:
        die("helper emitted invalid chunk size")
    chunks = max(1, math.ceil(metadata["plaintext_length"] / metadata["chunk_size"]))
    if chunks > MAX_CHUNKS_PER_OBJECT:
        die("helper plaintext exceeds 2^18 chunk limit")
    return metadata


def exact_metadata(result: dict[str, Any], expected: dict[str, Any]) -> dict[str, Any]:
    metadata = _metadata_from_result(result)
    if metadata != expected:
        die("helper authenticated metadata mismatch")
    return metadata


def source_metadata(
    root: str, logical: str, key_id: str, sequence: int, snapshot_id: str,
    release_id: str,
) -> dict[str, Any]:
    before = os.lstat(root)
    if not stat.S_ISREG(before.st_mode):
        die("unsupported snapshot object")
    if before.st_size > MAX_PLAINTEXT_BYTES:
        die("snapshot regular object exceeds 1 GiB preflight")
    chunks = max(1, math.ceil(before.st_size / CHUNK_SIZE))
    if chunks > MAX_CHUNKS_PER_OBJECT:
        die("snapshot regular object exceeds 2^18 chunk preflight")
    if sequence < 0 or sequence >= MAX_OBJECT_SEQUENCE:
        die("snapshot key object sequence exceeds rotation limit")
    return {
        "format_version": 2,
        "snapshot_id": snapshot_id,
        "release_id": release_id,
        "key_id": key_id,
        "key_object_sequence": sequence,
        "logical_path": logical,
        "uid": before.st_uid,
        "gid": before.st_gid,
        "mode": stat.S_IMODE(before.st_mode),
        "source_device": before.st_dev,
        "source_inode": before.st_ino,
        "plaintext_length": before.st_size,
        "source_mtime_ns": before.st_mtime_ns,
        "source_ctime_ns": before.st_ctime_ns,
        "chunk_size": CHUNK_SIZE,
    }


def _expected_arguments(metadata: dict[str, Any]) -> list[str]:
    flags = {
        "snapshot_id": "expect-snapshot-id",
        "release_id": "expect-release-id",
        "key_id": "expect-key-id",
        "key_object_sequence": "expect-key-object-sequence",
        "logical_path": "expect-logical-path",
        "uid": "expect-uid",
        "gid": "expect-gid",
        "mode": "expect-mode",
        "source_device": "expect-device",
        "source_inode": "expect-inode",
        "plaintext_length": "expect-plaintext-length",
        "source_mtime_ns": "expect-mtime-ns",
        "source_ctime_ns": "expect-ctime-ns",
        "chunk_size": "expect-chunk-size",
    }
    arguments: list[str] = []
    for field in METADATA_FIELDS[1:]:
        arguments.extend(["--" + flags[field], str(metadata[field])])
    return arguments


def _verify_ciphertext(
    helper: str, key: str, path: str, expected: dict[str, Any],
    receipt: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    command = [helper, "verify", "--key-file", key, "--input", path]
    if receipt is not None:
        if receipt.get("final_identity_known") is True:
            command.extend([
                "--expect-final-device", str(receipt["final_device"]),
                "--expect-final-inode", str(receipt["final_inode"]),
            ])
    code, result = _run(command, "snapshot-crypt verify")
    if code != 0:
        die("snapshot ciphertext verification failed")
    if result.get("status") != "verified" or result.get("input") != path:
        die("snapshot-crypt verify returned an invalid result")
    exact_metadata(result, expected)
    verified_receipt = canonical_receipt(result, path)
    if receipt is not None and receipt.get("final_identity_known") is True:
        for field in RECEIPT_FIELDS[1:]:
            if verified_receipt[field] != receipt[field]:
                die("ciphertext reconciliation receipt mismatch")
    return result, verified_receipt


def encrypt_object(
    helper: str, key: str, key_id: str, source: str, output: str,
    expected: dict[str, Any],
) -> dict[str, Any]:
    command = [
        helper, "encrypt", "--key-file", key, "--key-id", key_id,
        "--key-object-sequence", str(expected["key_object_sequence"]),
        "--input", source, "--output", output, "--snapshot-id",
        expected["snapshot_id"], "--release-id", expected["release_id"],
        "--logical-path", expected["logical_path"], "--source-contract", "quiesced",
        "--chunk-size", str(expected["chunk_size"]),
    ]
    code, result = _run(command, "snapshot-crypt encrypt")
    if code == 0:
        if result.get("status") != "encrypted" or result.get("output") != output:
            die("snapshot-crypt encrypt returned an invalid result")
        exact_metadata(result, expected)
        return canonical_receipt(result, output)
    if code not in PUBLICATION_EXITS:
        die("snapshot encryption failed")
    receipt = canonical_failure(result, code, "encrypt", output, PUBLICATION_EXITS[code][1])
    if code == 10:
        die("snapshot encryption failed before commit")
    _, verified_receipt = _verify_ciphertext(helper, key, output, expected, receipt)
    return verified_receipt


def reconcile_plaintext(
    helper: str, key: str, source: str, destination: str, expected: dict[str, Any],
) -> dict[str, Any]:
    command = [helper, "reconcile-publish", "--key-file", key, "--input", source,
               "--destination", destination, *_expected_arguments(expected)]
    code, result = _run(command, "snapshot-crypt reconcile-publish")
    if code != 0:
        die("snapshot plaintext reconciliation failed")
    if result.get("status") != "reconciled" or result.get("destination") != destination:
        die("snapshot plaintext reconciliation returned an invalid result")
    exact_metadata(result, expected)
    return canonical_receipt(result, destination)


def decrypt_publish(
    helper: str, key: str, source: str, destination: str, expected: dict[str, Any],
) -> dict[str, Any]:
    command = [helper, "decrypt-publish", "--key-file", key, "--input", source,
               "--destination", destination, *_expected_arguments(expected)]
    code, result = _run(command, "snapshot-crypt decrypt-publish")
    if code == 0:
        if result.get("status") != "published" or result.get("destination") != destination:
            die("snapshot-crypt decrypt-publish returned an invalid result")
        exact_metadata(result, expected)
        return canonical_receipt(result, destination)
    if code not in PUBLICATION_EXITS:
        die("snapshot plaintext publication failed")
    action = "reconcile-publish" if code != 10 else "none"
    canonical_failure(result, code, "decrypt-publish", destination, action)
    if code == 10:
        die("snapshot plaintext publication failed before commit")
    # Do not re-run decrypt-publish after 20/21/30. Reconcile decrypts into a
    # comparison writer and checks every authenticated metadata field instead.
    return reconcile_plaintext(helper, key, source, destination, expected)


def load_manifest(snapshot: str) -> list[tuple[str, str]]:
    path = os.path.join(snapshot, "manifest")
    try:
        descriptor = os.open(path, os.O_RDONLY | O_NOFOLLOW)
    except OSError:
        die("invalid snapshot manifest")
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_MANIFEST_BYTES:
            die("invalid snapshot manifest")
        payload = b""
        while True:
            block = os.read(descriptor, min(65536, MAX_MANIFEST_BYTES + 1 - len(payload)))
            if not block:
                break
            payload += block
            if len(payload) > MAX_MANIFEST_BYTES:
                die("invalid snapshot manifest")
        if not payload.endswith(b"\n") or b"\r" in payload or b"\x00" in payload:
            die("invalid snapshot manifest")
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        die("invalid snapshot manifest")
    finally:
        os.close(descriptor)
    entries: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) != 2 or parts[0] not in ("present", "absent"):
            die("invalid snapshot manifest")
        logical = canonical(parts[1])
        if logical in seen:
            die("duplicate snapshot logical root")
        seen.add(logical)
        entries.append((parts[0], logical))
    if not entries or len(entries) > MAX_RECORDS:
        die("invalid snapshot manifest")
    for logical in seen:
        components = logical.lstrip("/").split("/")
        for index in range(1, len(components)):
            if "/" + "/".join(components[:index]) in seen:
                die("overlapping snapshot logical roots")
    return entries


def _walk_preflight(root: str, logical: str, records: list[dict[str, Any]]) -> None:
    try:
        info = os.lstat(root)
    except OSError:
        die("snapshot source is missing")
    if len(records) >= MAX_RECORDS:
        die("snapshot object count exceeds preflight limit")
    item: dict[str, Any] = {
        "logical_path": canonical(logical), "uid": info.st_uid,
        "gid": info.st_gid, "mode": stat.S_IMODE(info.st_mode),
    }
    if stat.S_ISREG(info.st_mode):
        if info.st_size > MAX_PLAINTEXT_BYTES:
            die("snapshot regular object exceeds 1 GiB preflight")
        if max(1, math.ceil(info.st_size / CHUNK_SIZE)) > MAX_CHUNKS_PER_OBJECT:
            die("snapshot regular object exceeds 2^18 chunk preflight")
        item["kind"] = "regular"
        records.append(item)
        return
    if stat.S_ISLNK(info.st_mode):
        target = os.readlink(root)
        if not target or "\x00" in target:
            die("unsafe snapshot symlink")
        item.update(kind="symlink", target=target)
        records.append(item)
        return
    if not stat.S_ISDIR(info.st_mode):
        die("unsupported snapshot object")
    item["kind"] = "directory"
    records.append(item)
    try:
        names = sorted(os.listdir(root))
    except OSError:
        die("snapshot source directory is unreadable")
    for name in names:
        if not name or name in (".", "..") or "/" in name or "\x00" in name:
            die("unsafe snapshot source member")
        _walk_preflight(os.path.join(root, name), logical + "/" + name, records)


def _ledger_path(ledger: str, key_id: str) -> str:
    if not os.path.isabs(ledger) or os.path.normpath(ledger) != ledger:
        die("unsafe key sequence ledger path")
    expected = "key-sequence-" + hashlib.sha256(key_id.encode("utf-8")).hexdigest() + ".json"
    if os.path.basename(ledger) != expected:
        die("key sequence ledger does not bind the key id")
    return ledger


def allocate_sequences(ledger: str, key_id: str, count: int) -> int:
    if count < 0 or count >= MAX_OBJECT_SEQUENCE:
        die("invalid key sequence allocation")
    ledger = _ledger_path(ledger, key_id)
    parent = os.path.dirname(ledger)
    if not os.path.isdir(parent) or os.path.islink(parent):
        die("unsafe key sequence ledger directory")
    try:
        descriptor = os.open(ledger, os.O_RDONLY | O_NOFOLLOW)
    except FileNotFoundError:
        next_sequence = 0
    except OSError:
        die("unsafe key sequence ledger")
    else:
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode)
                    or (os.name == "posix" and stat.S_IMODE(info.st_mode) != 0o600)
                    or info.st_size > 4096):
                die("unsafe key sequence ledger")
            payload = os.read(descriptor, 4097)
            value = json.loads(payload.decode("utf-8"))
            if set(value) != {"version", "key_id", "next_sequence"} or value["version"] != 1:
                die("invalid key sequence ledger")
            if value["key_id"] != key_id or not isinstance(value["next_sequence"], int):
                die("invalid key sequence ledger")
            next_sequence = value["next_sequence"]
        except (ValueError, UnicodeDecodeError, TypeError):
            die("invalid key sequence ledger")
        finally:
            os.close(descriptor)
    if next_sequence < 0 or next_sequence + count > MAX_OBJECT_SEQUENCE:
        die("snapshot key id exhausted; provision a new key id")
    payload = (json.dumps({"version": 1, "key_id": key_id,
                          "next_sequence": next_sequence + count},
                          sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    temporary = ledger + ".tmp"
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW, 0o600)
        try:
            _write_all(descriptor, payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, ledger)
        if os.name == "posix":
            parent_fd = os.open(parent, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
    except OSError as error:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        die("could not durably allocate key object sequences: " + str(error))
    return next_sequence


def capture(
    snapshot: str, source_root: str, key: str, key_id: str, helper: str,
    snapshot_id: str, release_id: str, ledger: str,
) -> None:
    key_id = identifier(key_id, "key id")
    snapshot_id = identifier(snapshot_id, "snapshot id")
    release_id = identifier(release_id, "release id")
    entries = load_manifest(snapshot)
    if os.path.lexists(os.path.join(snapshot, "objects")) or os.path.lexists(os.path.join(snapshot, "payload.manifest.json")):
        die("snapshot payload destination already exists")
    records: list[dict[str, Any]] = []
    for state, logical in entries:
        if state == "absent":
            records.append({"logical_path": logical, "kind": "absent"})
        else:
            _walk_preflight(os.path.join(source_root, logical.lstrip("/")), logical, records)
    regulars = [item for item in records if item["kind"] == "regular"]
    first_sequence = allocate_sequences(ledger, key_id, len(regulars))
    objects = os.path.join(snapshot, "objects")
    os.mkdir(objects, 0o700)
    sequence = first_sequence
    for item in records:
        if item["kind"] != "regular":
            continue
        logical = item["logical_path"]
        source = os.path.join(source_root, logical.lstrip("/"))
        expected = source_metadata(source, logical, key_id, sequence, snapshot_id, release_id)
        for field in ("uid", "gid", "mode"):
            if expected[field] != item[field]:
                die("snapshot source changed after preflight")
        name = object_name(logical)
        output = os.path.join(objects, name)
        receipt = encrypt_object(helper, key, key_id, source, output, expected)
        item.update(expected, object=name, cipher_sha256=digest(output), ciphertext_receipt=receipt)
        sequence += 1
    if sequence != first_sequence + len(regulars):
        die("snapshot sequence allocation mismatch")
    _validate_payload_records(records, entries, key_id)
    payload = {
        "format": "pgw-encrypted-snapshot-v2", "snapshot_id": snapshot_id,
        "release_id": release_id, "key_id": key_id, "records":
        sorted(records, key=lambda item: item["logical_path"]),
    }
    temporary = os.path.join(snapshot, ".payload-manifest.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW, 0o600)
    try:
        _write_all(descriptor, (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, os.path.join(snapshot, "payload.manifest.json"))
    directory = os.open(snapshot, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _load_payload(snapshot: str) -> dict[str, Any]:
    path = os.path.join(snapshot, "payload.manifest.json")
    try:
        descriptor = os.open(path, os.O_RDONLY | O_NOFOLLOW)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_MANIFEST_BYTES:
                die("invalid encrypted payload manifest")
            data = os.read(descriptor, MAX_MANIFEST_BYTES + 1)
        finally:
            os.close(descriptor)
        payload = json.loads(data.decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        die("invalid encrypted payload manifest")
    if not isinstance(payload, dict) or set(payload) != {"format", "snapshot_id", "release_id", "key_id", "records"}:
        die("invalid encrypted payload manifest")
    if payload["format"] != "pgw-encrypted-snapshot-v2":
        die("invalid encrypted payload manifest")
    identifier(payload["snapshot_id"], "snapshot id")
    identifier(payload["release_id"], "release id")
    identifier(payload["key_id"], "key id")
    if not isinstance(payload["records"], list):
        die("invalid encrypted payload manifest")
    return payload


def _validate_payload_records(
    records: list[dict[str, Any]], entries: list[tuple[str, str]], key_id: str,
) -> None:
    expected_roots = {logical: state for state, logical in entries}
    seen_paths: set[str] = set()
    seen_sequences: set[int] = set()
    regular_count = 0
    for item in records:
        if not isinstance(item, dict):
            die("invalid payload record")
        logical = canonical(item.get("logical_path"))
        if logical in seen_paths:
            die("duplicate payload logical path")
        seen_paths.add(logical)
        kind = item.get("kind")
        root = next((candidate for candidate in expected_roots if logical == candidate or logical.startswith(candidate + "/")), None)
        if root is None:
            die("payload record is outside manifest roots")
        if kind == "absent":
            if logical != root or expected_roots[root] != "absent" or set(item) != {"logical_path", "kind"}:
                die("invalid absent payload record")
            continue
        if expected_roots[root] != "present":
            die("payload records under absent roots are forbidden")
        common = {"logical_path", "kind", "uid", "gid", "mode"}
        if kind == "directory":
            if set(item) != common:
                die("invalid directory payload record")
        elif kind == "symlink":
            if set(item) != common | {"target"} or not isinstance(item["target"], str) or not item["target"] or "\x00" in item["target"]:
                die("invalid symlink payload record")
        elif kind == "regular":
            regular_count += 1
            required = common | set(METADATA_FIELDS) | {"object", "cipher_sha256", "ciphertext_receipt"}
            if set(item) != required:
                die("invalid regular payload record")
            expected = {field: item[field] for field in METADATA_FIELDS}
            _metadata_from_result(expected)
            if expected["logical_path"] != logical or expected["key_id"] != key_id:
                die("payload regular metadata mismatch")
            sequence = expected["key_object_sequence"]
            if sequence in seen_sequences:
                die("duplicate key object sequence")
            seen_sequences.add(sequence)
            if item["object"] != object_name(logical) or not isinstance(item["cipher_sha256"], str) or HEX_PATTERN.fullmatch(item["cipher_sha256"]) is None:
                die("invalid payload ciphertext object")
            receipt = item["ciphertext_receipt"]
            if not isinstance(receipt, dict) or set(receipt) != set(RECEIPT_FIELDS):
                die("invalid payload ciphertext receipt")
            canonical_receipt({**receipt, "output": "/receipt/object"}, "/receipt/object")
        else:
            die("invalid payload record kind")
        for field in ("uid", "gid", "mode"):
            _integer(item.get(field), field)
        if item["mode"] > 0o7777:
            die("invalid payload object mode")
    if regular_count > MAX_RECORDS or set(expected_roots) - {path for path in seen_paths if path in expected_roots}:
        die("payload omitted manifest root")


def verify(snapshot: str, key: str, helper: str) -> None:
    entries = load_manifest(snapshot)
    payload = _load_payload(snapshot)
    records = payload["records"]
    _validate_payload_records(records, entries, payload["key_id"])
    expected_names: set[str] = set()
    for item in records:
        if item["kind"] != "regular":
            continue
        expected = {field: item[field] for field in METADATA_FIELDS}
        name = item["object"]
        expected_names.add(name)
        path = os.path.join(snapshot, "objects", name)
        try:
            cipher_digest = digest(path)
        except OSError:
            die("ciphertext object is missing or unreadable")
        if cipher_digest != item["cipher_sha256"]:
            die("ciphertext digest mismatch")
        receipt = item["ciphertext_receipt"]
        _, actual_receipt = _verify_ciphertext(helper, key, path, expected, receipt)
        if actual_receipt != receipt:
            die("ciphertext receipt mismatch")
    try:
        actual_names = set(os.listdir(os.path.join(snapshot, "objects")))
    except OSError:
        die("encrypted payload object directory is unavailable")
    if actual_names != expected_names:
        die("encrypted payload object set mismatch")


def _secure_stage_parent(destination: str, expected_uid: int) -> tuple[int, str]:
    if not os.path.isabs(destination) or os.path.normpath(destination) != destination:
        die("restore stage path is unsafe")
    parent_path, name = os.path.dirname(destination), os.path.basename(destination)
    if not name or name in (".", ".."):
        die("restore stage name is unsafe")
    descriptor = os.open(os.sep, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
    try:
        for part in (piece for piece in parent_path.split(os.sep) if piece):
            child = os.open(part, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW, dir_fd=descriptor)
            info = os.fstat(child)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, expected_uid) or info.st_mode & 0o022:
                os.close(child)
                die("restore stage parent is unsafe")
            os.close(descriptor)
            descriptor = child
        return descriptor, name
    except BaseException:
        os.close(descriptor)
        raise


def create_private_stage(destination: str) -> None:
    expected_uid = os.geteuid() if hasattr(os, "geteuid") else 0
    parent, name = _secure_stage_parent(destination, expected_uid)
    try:
        try:
            os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            die("restore stage already exists")
        os.mkdir(name, 0o700, dir_fd=parent)
        stage = os.open(name, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW, dir_fd=parent)
        try:
            info = os.fstat(stage)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != expected_uid or stat.S_IMODE(info.st_mode) != 0o700:
                die("restore stage ownership is unsafe")
            os.fsync(stage)
        finally:
            os.close(stage)
        os.fsync(parent)
    finally:
        os.close(parent)


def _remove_at(parent: int, name: str) -> None:
    info = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if stat.S_ISDIR(info.st_mode):
        child = os.open(name, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW, dir_fd=parent)
        try:
            for entry in os.listdir(child):
                _remove_at(child, entry)
            os.fsync(child)
        finally:
            os.close(child)
        os.rmdir(name, dir_fd=parent)
    else:
        os.unlink(name, dir_fd=parent)


def remove_private_stage(destination: str, expected_uid: int) -> None:
    parent, name = _secure_stage_parent(destination, expected_uid)
    try:
        stage = os.open(name, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW, dir_fd=parent)
        try:
            info = os.fstat(stage)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != expected_uid or stat.S_IMODE(info.st_mode) != 0o700:
                die("restore stage ownership is unsafe")
            for entry in os.listdir(stage):
                _remove_at(stage, entry)
            os.fsync(stage)
        finally:
            os.close(stage)
        os.rmdir(name, dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(parent)


def remove_legacy_report_runtime(destination: str, expected_uid: int) -> None:
    """Remove only the fixed private legacy-import report directory."""
    if os.path.basename(destination) != "legacy-import":
        die("legacy import runtime name is unsafe")
    parent, name = _secure_stage_parent(destination, expected_uid)
    try:
        runtime = os.open(name, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW, dir_fd=parent)
        try:
            info = os.fstat(runtime)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != expected_uid or
                    stat.S_IMODE(info.st_mode) != 0o700):
                die("legacy import runtime ownership is unsafe")
            if os.listdir(runtime) != ["report.json"]:
                die("unexpected legacy import runtime contents")
            report_info = os.stat("report.json", dir_fd=runtime, follow_symlinks=False)
            if (not stat.S_ISREG(report_info.st_mode) or report_info.st_uid != expected_uid or
                    stat.S_IMODE(report_info.st_mode) != 0o600):
                die("legacy import report is unsafe")
            os.unlink("report.json", dir_fd=runtime)
            os.fsync(runtime)
        finally:
            os.close(runtime)
        os.rmdir(name, dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(parent)


def materialize(snapshot: str, key: str, helper: str, destination: str) -> None:
    # Verify every ciphertext and receipt before creating the private stage. A
    # wrong key, missing/extra/truncated/tampered object leaves no plaintext.
    verify(snapshot, key, helper)
    payload = _load_payload(snapshot)
    create_private_stage(destination)
    files = os.path.join(destination, "files")
    try:
        os.mkdir(files, 0o700)
        records = payload["records"]
        for item in sorted((entry for entry in records if entry["kind"] == "directory"), key=lambda entry: entry["logical_path"].count("/")):
            target = os.path.join(files, item["logical_path"].lstrip("/"))
            parent = os.path.dirname(target)
            if not os.path.isdir(parent) or os.path.islink(parent):
                die("unsafe restore parent")
            os.mkdir(target, 0o700)
        for item in sorted((entry for entry in records if entry["kind"] in ("regular", "symlink")), key=lambda entry: entry["logical_path"]):
            target = os.path.join(files, item["logical_path"].lstrip("/"))
            parent = os.path.dirname(target)
            if not os.path.isdir(parent) or os.path.islink(parent):
                die("unsafe restore parent")
            if item["kind"] == "symlink":
                os.symlink(item["target"], target)
                os.chown(target, item["uid"], item["gid"], follow_symlinks=False)
                continue
            expected = {field: item[field] for field in METADATA_FIELDS}
            decrypt_publish(helper, key, os.path.join(snapshot, "objects", item["object"]), target, expected)
        for item in sorted((entry for entry in records if entry["kind"] == "directory"), key=lambda entry: entry["logical_path"].count("/"), reverse=True):
            target = os.path.join(files, item["logical_path"].lstrip("/"))
            descriptor = os.open(target, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
            try:
                os.fchown(descriptor, item["uid"], item["gid"])
                os.fchmod(descriptor, item["mode"])
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        source = os.path.join(snapshot, "manifest")
        target = os.path.join(destination, "manifest")
        with open(source, "rb") as source_file:
            payload_bytes = source_file.read(MAX_MANIFEST_BYTES + 1)
        if len(payload_bytes) > MAX_MANIFEST_BYTES:
            die("snapshot manifest exceeds materialization bound")
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW, 0o600)
        try:
            _write_all(descriptor, payload_bytes)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        stage = os.open(destination, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
        try:
            os.fsync(stage)
        finally:
            os.close(stage)
    except BaseException:
        raise


def main() -> None:
    if len(sys.argv) < 2:
        die("usage")
    command = sys.argv[1]
    if command == "capture" and len(sys.argv) == 10:
        capture(*sys.argv[2:])
        return
    if command == "verify" and len(sys.argv) == 5:
        verify(*sys.argv[2:])
        return
    if command == "materialize" and len(sys.argv) == 6:
        materialize(*sys.argv[2:])
        return
    if command == "remove-stage" and len(sys.argv) == 4:
        remove_private_stage(sys.argv[2], int(sys.argv[3]))
        return
    if command == "remove-legacy-report" and len(sys.argv) == 4:
        remove_legacy_report_runtime(sys.argv[2], int(sys.argv[3]))
        return
    die("usage")


if __name__ == "__main__":
    main()
