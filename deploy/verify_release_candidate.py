#!/usr/bin/env python3
"""Strict parser and verifier for a staged PGW release candidate."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import sys
from pathlib import Path

HEX = re.compile(r"[0-9a-f]{64}")
SHA = re.compile(r"[0-9a-f]{40}")
SAFE_PATH = re.compile(r"[A-Za-z0-9._@+~-]+(?:/[A-Za-z0-9._@+~-]+)*")
SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
EXPECTED_BINARIES = (
    "release/artifacts/pgw-api",
    "release/artifacts/pgw-agent",
    "release/artifacts/pgw-fwd",
    "release/artifacts/pgw-ui",
    "release/artifacts/pgw-health",
    "release/artifacts/pgw-snapshot-crypt",
    "pgw-release-launcher",
)


class CandidateError(Exception):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def lines(path: Path) -> list[str]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise CandidateError(f"cannot read {path.name}: {error}") from error
    if b"\x00" in raw or b"\r" in raw or not raw.endswith(b"\n"):
        raise CandidateError(f"non-canonical text file: {path.name}")
    try:
        return raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise CandidateError(f"non-UTF8 manifest: {path.name}") from error


def exact_map(path: Path, expected: tuple[str, ...]) -> dict[str, str]:
    parsed: dict[str, str] = {}
    file_lines = lines(path)
    if len(file_lines) != len(expected):
        raise CandidateError(f"wrong field count in {path.name}")
    for index, key in enumerate(expected):
        parts = file_lines[index].split(" ")
        if len(parts) != 2 or parts[0] != key or not parts[1]:
            raise CandidateError(f"invalid or out-of-order {key} in {path.name}")
        parsed[key] = parts[1]
    return parsed


def regular_tree(root: Path) -> dict[str, tuple[int, int, str]]:
    result: dict[str, tuple[int, int, str]] = {}
    for current, directories, filenames in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        for name in directories + filenames:
            path = current_path / name
            relative = path.relative_to(root).as_posix()
            if not SAFE_PATH.fullmatch(relative) or any(part in (".", "..") for part in relative.split("/")):
                raise CandidateError(f"unsafe tree path: {relative}")
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                raise CandidateError(f"special node in candidate: {relative}")
            if stat.S_ISREG(info.st_mode):
                result[relative] = (info.st_mode & 0o777, info.st_size, sha256(path))
    return result


def verify_source(assembly: Path, version: dict[str, str]) -> None:
    manifest_lines = lines(assembly / "source.manifest")
    expected_prefix = [
        "format pgw-source-snapshot-v1",
        f"commit {version['source_commit']}",
        f"tree {version['source_tree']}",
        f"dirty {version['source_dirty']}",
    ]
    if manifest_lines[:4] != expected_prefix:
        raise CandidateError("source manifest identity mismatch")
    records: dict[str, tuple[int, int, str]] = {}
    record_re = re.compile(r"file ([0-9a-f]{64}) (0[0-7]{3}) ([A-Za-z0-9._@+~-]+(?:/[A-Za-z0-9._@+~-]+)*)")
    for line in manifest_lines[4:]:
        match = record_re.fullmatch(line)
        if not match:
            raise CandidateError("malformed source manifest record")
        digest, mode, relative = match.groups()
        if relative in records or any(part in (".", "..") for part in relative.split("/")):
            raise CandidateError("duplicate or traversing source record")
        source_file = assembly / "source" / relative
        records[relative] = (int(mode, 8), source_file.stat().st_size if source_file.is_file() else -1, digest)
    actual = regular_tree(assembly / "source")
    if actual != records:
        raise CandidateError("source manifest is not an exact source-tree inventory")


def verify_release_manifest(assembly: Path, release_id: str) -> str:
    trust = exact_map(
        assembly / "release-trust.manifest",
        ("format", "release_id", "manifest_sha256"),
    )
    if trust != {
        "format": "pgw-trust-v1",
        "release_id": release_id,
        "manifest_sha256": trust["manifest_sha256"],
    } or not HEX.fullmatch(trust["manifest_sha256"]):
        raise CandidateError("invalid release trust manifest")
    release_manifest = assembly / "release" / "release.manifest"
    actual_manifest_digest = sha256(release_manifest)
    if actual_manifest_digest != trust["manifest_sha256"]:
        raise CandidateError("release manifest trust digest mismatch")
    manifest_lines = lines(release_manifest)
    if not manifest_lines or manifest_lines[0] != "format pgw-release-v1":
        raise CandidateError("invalid release manifest header")
    records: dict[str, tuple[int, int, str]] = {}
    record_re = re.compile(r"file ([0-9a-f]{64}) (0[0-7]{3}) ([A-Za-z0-9._@+~-]+(?:/[A-Za-z0-9._@+~-]+)*)")
    for line in manifest_lines[1:]:
        match = record_re.fullmatch(line)
        if not match:
            raise CandidateError("malformed release manifest record")
        digest, mode, relative = match.groups()
        if relative in records or any(part in (".", "..") for part in relative.split("/")):
            raise CandidateError("duplicate or traversing release record")
        release_file = assembly / "release" / relative
        records[relative] = (int(mode, 8), release_file.stat().st_size if release_file.is_file() else -1, digest)
    actual = regular_tree(assembly / "release")
    actual.pop("release.manifest", None)
    if actual != records:
        raise CandidateError("release manifest is not an exact release-tree inventory")
    return actual_manifest_digest


def verify_migrations(assembly: Path) -> None:
    ledger = lines(assembly / "migration.manifest")
    if len(ledger) < 4 or ledger[0] != "format pgw-migrations-v1":
        raise CandidateError("invalid migration ledger header")
    target_match = re.fullmatch(r"schema_target ([1-9][0-9]*)", ledger[1])
    count_match = re.fullmatch(r"migration_count ([1-9][0-9]*)", ledger[2])
    if not target_match or not count_match:
        raise CandidateError("invalid migration ledger counts")
    target, count = int(target_match.group(1)), int(count_match.group(1))
    if target != count or len(ledger) != count + 3:
        raise CandidateError("migration ledger count mismatch")
    seen: set[str] = set()
    for expected, line in enumerate(ledger[3:], start=1):
        match = re.fullmatch(r"migration ([1-9][0-9]*) ([0-9a-f]{64}) ([0-9]{4}_[A-Za-z0-9._-]+[.]sql)", line)
        if not match or int(match.group(1)) != expected or match.group(3) in seen:
            raise CandidateError("invalid migration record")
        seen.add(match.group(3))


def verify_build_proof(assembly: Path) -> None:
    proof_lines = lines(assembly / "build-proof.manifest")
    if len(proof_lines) != 3 + len(EXPECTED_BINARIES):
        raise CandidateError("wrong build proof record count")
    if proof_lines[0] != "format pgw-build-proof-v2" or proof_lines[2] != "deterministic_builds 2":
        raise CandidateError("invalid build proof header")
    module_match = re.fullmatch(r"module_verify_sha256 ([0-9a-f]{64})", proof_lines[1])
    module_proof = assembly / "build-proof" / "go-mod-verify.txt"
    if not module_match or sha256(module_proof) != module_match.group(1):
        raise CandidateError("module verification proof mismatch")
    record_re = re.compile(
        r"binary ([0-9a-f]{64}) ([A-Za-z0-9._@+~-]+(?:/[A-Za-z0-9._@+~-]+)*) "
        r"cgo=0 dynamic=absent rebuild=identical proof_sha256=([0-9a-f]{64})"
    )
    seen: set[str] = set()
    for line in proof_lines[3:]:
        match = record_re.fullmatch(line)
        if not match:
            raise CandidateError("malformed binary proof record")
        digest, relative, proof_digest = match.groups()
        if relative not in EXPECTED_BINARIES or relative in seen:
            raise CandidateError("unexpected or duplicate binary proof")
        seen.add(relative)
        binary = assembly / relative
        if not binary.is_file() or binary.is_symlink() or sha256(binary) != digest:
            raise CandidateError("binary proof digest mismatch")
        proof_name = Path(relative).name
        digest_input = bytearray()
        for suffix in ("go-version.txt", "file.txt", "elf-header.txt", "elf-dynamic.txt"):
            proof_file = assembly / "build-proof" / f"{proof_name}.{suffix}"
            digest_input.extend(suffix.encode())
            digest_input.append(0)
            digest_input.extend(sha256(proof_file).encode())
            digest_input.append(0)
        if hashlib.sha256(digest_input).hexdigest() != proof_digest:
            raise CandidateError("binary supporting proof mismatch")
    if seen != set(EXPECTED_BINARIES):
        raise CandidateError("binary proof set is incomplete")


def verify(assembly: Path) -> tuple[str, str, str]:
    required = (
        "source.manifest",
        "version.manifest",
        "migration.manifest",
        "build-proof.manifest",
        "release-trust.manifest",
        "release/release.manifest",
        "pgw-release-launcher",
    )
    for relative in required:
        path = assembly / relative
        if not path.is_file() or path.is_symlink():
            raise CandidateError(f"missing required regular file: {relative}")
    version = exact_map(
        assembly / "version.manifest",
        (
            "format", "release_id", "candidate_only", "promotion_authority",
            "source_commit", "source_tree", "source_dirty", "source_commit_time",
            "go_module", "go_version", "target", "cgo_enabled", "build_flags",
            "module_verification", "deterministic_rebuilds",
        ),
    )
    if version["format"] != "pgw-version-v2" or not SAFE_ID.fullmatch(version["release_id"]):
        raise CandidateError("invalid candidate version identity")
    fixed = {
        "candidate_only": "true",
        "promotion_authority": "external-github-attestation",
        "target": "linux/amd64",
        "cgo_enabled": "0",
        "build_flags": "-trimpath,-buildvcs=false,-ldflags=-s_-w",
        "module_verification": "same-run-offline",
        "deterministic_rebuilds": "2",
    }
    if any(version[key] != value for key, value in fixed.items()):
        raise CandidateError("candidate attempted to self-assert promotion or build policy")
    if not SHA.fullmatch(version["source_commit"]) or not SHA.fullmatch(version["source_tree"]):
        raise CandidateError("invalid source Git identity")
    if version["source_dirty"] not in ("true", "false"):
        raise CandidateError("invalid source dirty state")
    if not re.fullmatch(r"go1[.][0-9]+[.][0-9]+", version["go_version"]):
        raise CandidateError("Go toolchain is not pinned exactly")
    regular_tree(assembly)
    verify_source(assembly, version)
    release_digest = verify_release_manifest(assembly, version["release_id"])
    verify_migrations(assembly)
    verify_build_proof(assembly)
    return version["release_id"], version["source_commit"], release_digest


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: verify_release_candidate.py ASSEMBLY", file=sys.stderr)
        return 2
    try:
        release_id, source_commit, release_digest = verify(Path(sys.argv[1]))
    except (OSError, UnicodeError, CandidateError) as error:
        print(f"release candidate rejected: {error}", file=sys.stderr)
        return 65
    print(f"release_id {release_id}")
    print(f"source_commit {source_commit}")
    print(f"release_manifest_sha256 {release_digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
