#!/usr/bin/env python3
"""Strict parser for externally signed PGW full-system raw evidence."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import sys
from pathlib import Path

HEX = re.compile(r"[0-9a-f]{64}")
SHA = re.compile(r"[0-9a-f]{40}")
SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
RUN_ID = re.compile(r"[1-9][0-9]*")
RAW_FILES = (
    "raw/base-firewall-sysctl-services.txt",
    "raw/credential-transition.txt",
    "raw/database-integrity.txt",
    "raw/fail-close-transcript.txt",
    "raw/lifecycle.log",
    "raw/migration-transcript.txt",
    "raw/network-capture.pcap",
    "raw/nft-counters.json",
    "raw/nft-ruleset.json",
    "raw/processes-state.txt",
    "raw/rollback-transcript.txt",
    "raw/services-state.txt",
)
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_PAYLOAD_BYTES = 256 * 1024 * 1024
MAX_MANIFEST_BYTES = 4096
MAX_INDEX_BYTES = 8192
MAX_SIGNATURE_BYTES = 16 * 1024


class EvidenceError(Exception):
    pass


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            result.update(chunk)
    return result.hexdigest()


def canonical_lines(path: Path, byte_limit: int) -> list[str]:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > byte_limit:
        raise EvidenceError(f"metadata exceeds size/type policy: {path.name}")
    raw = path.read_bytes()
    if not raw.endswith(b"\n") or b"\r" in raw or b"\x00" in raw:
        raise EvidenceError(f"non-canonical text: {path.name}")
    try:
        return raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise EvidenceError(f"non-UTF8 text: {path.name}") from error


def exact_fields(path: Path, keys: tuple[str, ...]) -> dict[str, str]:
    source = canonical_lines(path, MAX_MANIFEST_BYTES)
    if len(source) != len(keys):
        raise EvidenceError(f"wrong field count: {path.name}")
    result: dict[str, str] = {}
    for index, key in enumerate(keys):
        parts = source[index].split(" ")
        if len(parts) != 2 or parts[0] != key or not parts[1]:
            raise EvidenceError(f"invalid or out-of-order field {key}")
        result[key] = parts[1]
    return result


def verify_regular_tree(root: Path) -> None:
    for current, directories, files in os.walk(root, followlinks=False):
        for name in directories + files:
            path = Path(current) / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                raise EvidenceError(f"special node rejected: {path.relative_to(root).as_posix()}")


def payload_digest(records: dict[str, tuple[str, int]]) -> str:
    value = hashlib.sha256()
    for relative in sorted(records, key=os.fsencode):
        file_digest, size = records[relative]
        value.update(relative.encode("ascii"))
        value.update(b"\x00")
        value.update(file_digest.encode("ascii"))
        value.update(b"\x00")
        value.update(str(size).encode("ascii"))
        value.update(b"\x00")
    return value.hexdigest()


def verify(root: Path, release_id: str, release_manifest: str, source_sha: str, run_id: str) -> tuple[str, str]:
    if not SAFE_ID.fullmatch(release_id) or not HEX.fullmatch(release_manifest):
        raise EvidenceError("invalid expected release identity")
    if not SHA.fullmatch(source_sha) or not RUN_ID.fullmatch(run_id):
        raise EvidenceError("invalid expected source/run identity")
    if root.is_symlink() or not root.is_dir():
        raise EvidenceError("full-system evidence root must be a real directory")
    verify_regular_tree(root)
    expected_top = {
        "full-system-attestation.manifest",
        "full-system-attestation.sig",
        "full-system-evidence.index",
        "raw",
    }
    if {path.name for path in root.iterdir()} != expected_top:
        raise EvidenceError("external evidence has missing or extra top-level entries")
    if {path.relative_to(root).as_posix() for path in (root / "raw").iterdir()} != set(RAW_FILES):
        raise EvidenceError("raw evidence allowlist mismatch")

    index_path = root / "full-system-evidence.index"
    index_lines = canonical_lines(index_path, MAX_INDEX_BYTES)
    expected_prefix = [
        "format pgw-full-system-evidence-index-v1",
        f"release_id {release_id}",
        f"release_manifest_sha256 {release_manifest}",
        f"source_commit {source_sha}",
        "producer protected-ci",
        f"run_id {run_id}",
        f"file_count {len(RAW_FILES)}",
    ]
    if index_lines[: len(expected_prefix)] != expected_prefix or len(index_lines) != len(expected_prefix) + len(RAW_FILES):
        raise EvidenceError("invalid evidence index identity or record count")
    record_re = re.compile(r"file ([0-9a-f]{64}) ([1-9][0-9]*) (raw/[A-Za-z0-9._-]+)")
    records: dict[str, tuple[str, int]] = {}
    record_order: list[str] = []
    for line in index_lines[len(expected_prefix) :]:
        match = record_re.fullmatch(line)
        if not match:
            raise EvidenceError("malformed evidence index record")
        file_digest, size_text, relative = match.groups()
        if relative in records:
            raise EvidenceError("duplicate raw evidence record")
        size = int(size_text)
        if size > MAX_FILE_BYTES:
            raise EvidenceError("raw evidence file exceeds size policy")
        records[relative] = (file_digest, size)
        record_order.append(relative)
    if set(records) != set(RAW_FILES) or tuple(record_order) != RAW_FILES:
        raise EvidenceError("evidence index raw allowlist mismatch")
    if sum(size for _, size in records.values()) > MAX_PAYLOAD_BYTES:
        raise EvidenceError("raw evidence aggregate exceeds size policy")
    for relative, (expected_digest, expected_size) in records.items():
        path = root / relative
        if not path.is_file() or path.is_symlink():
            raise EvidenceError(f"raw evidence is not a regular file: {relative}")
        info = path.stat()
        if info.st_size != expected_size or digest(path) != expected_digest:
            raise EvidenceError(f"raw evidence digest/size mismatch: {relative}")

    index_digest = digest(index_path)
    raw_digest = payload_digest(records)
    manifest = exact_fields(
        root / "full-system-attestation.manifest",
        (
            "format", "release_id", "release_manifest_sha256", "source_commit",
            "transaction_model", "isolation", "private_namespaces", "credential_free",
            "binary_count", "ui_assets", "units_policy_tmpfiles", "credential_transition",
            "database_migration_integrity", "base_firewall_sysctl_services",
            "production_root_lifecycle", "rollback", "fail_close", "producer", "run_id",
            "evidence_index_sha256", "raw_payload_sha256",
        ),
    )
    exact = {
        "format": "pgw-full-system-attestation-v2",
        "release_id": release_id,
        "release_manifest_sha256": release_manifest,
        "source_commit": source_sha,
        "transaction_model": "full_system",
        "isolation": "vm-or-dedicated-rootfs",
        "private_namespaces": "user,pid,mount,network,ipc,uts",
        "credential_free": "true",
        "binary_count": "6",
        "ui_assets": "PASS",
        "units_policy_tmpfiles": "PASS",
        "credential_transition": "PASS",
        "database_migration_integrity": "PASS",
        "base_firewall_sysctl_services": "PASS",
        "production_root_lifecycle": "PASS",
        "rollback": "PASS",
        "fail_close": "PASS",
        "producer": "protected-ci",
        "run_id": run_id,
        "evidence_index_sha256": index_digest,
        "raw_payload_sha256": raw_digest,
    }
    if manifest != exact:
        raise EvidenceError("full-system manifest binding/policy mismatch")
    signature = root / "full-system-attestation.sig"
    if not signature.is_file() or signature.is_symlink() or not (64 <= signature.stat().st_size <= MAX_SIGNATURE_BYTES):
        raise EvidenceError("invalid detached signature file")
    return index_digest, raw_digest


def main() -> int:
    if len(sys.argv) != 6:
        print("usage: verify_full_system_evidence.py ROOT RELEASE_ID RELEASE_MANIFEST SOURCE_SHA RUN_ID", file=sys.stderr)
        return 2
    try:
        index_digest, raw_digest = verify(Path(sys.argv[1]), *sys.argv[2:])
    except (OSError, UnicodeError, EvidenceError) as error:
        print(f"full-system evidence rejected: {error}", file=sys.stderr)
        return 65
    print(f"evidence_index_sha256 {index_digest}")
    print(f"raw_payload_sha256 {raw_digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
