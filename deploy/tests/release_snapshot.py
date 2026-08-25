#!/usr/bin/env python3
"""Descriptor-first snapshot and strict PGW rehearsal manifest verifier."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import sys
from pathlib import Path


MAX_FILES = 512
MAX_BYTES = 512 * 1024 * 1024
PATH_RE = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._@+-]*(?:/[A-Za-z0-9][A-Za-z0-9._@+-]*)*"
)
SOURCE_PATH_RE = re.compile(
    r"[A-Za-z0-9._@+~-]+(?:/[A-Za-z0-9._@+~-]+)*"
)
HEX_RE = re.compile(r"[0-9a-f]{64}")
RELEASE_PATHS = {
    "deploy/install-pgw.sh",
    "artifacts/pgw-api",
    "artifacts/pgw-agent",
    "artifacts/pgw-fwd",
    "artifacts/pgw-ui",
    "artifacts/pgw-health",
    "artifacts/pgw-snapshot-crypt",
    "deploy/install-pgw-base.sh",
    "deploy/pgw-verify-base.sh",
    "deploy/pgw-verify-ui-bind.sh",
    "deploy/restore_snapshot.py",
    "deploy/snapshot_payload.py",
    "deploy/nftables.conf",
    "deploy/sysctl-pgw.conf",
    "deploy/sysusers.d/pgw.conf",
    "deploy/tmpfiles.d/pgw.conf",
    "deploy/polkit-1/rules.d/50-pgw-agent-forwarder.rules",
    "deploy/systemd/pgw-api.service",
    "deploy/systemd/pgw-agent.service",
    "deploy/systemd/pgw-fwd@.service",
    "deploy/systemd/pgw-ui.service",
    "deploy/systemd/pgw-health.service",
    "deploy/systemd/nftables.service.d/pgw.conf",
    "deploy/systemd/systemd-sysctl.service.d/pgw.conf",
    "deploy/ui-assets.sha256",
    "web/static/app.js",
    "web/static/styles.css",
    "web/static/login.js",
    "web/static/layout.css",
    "deploy/rehearse-release.sh",
    "deploy/tests/installer_harness.sh",
    "deploy/tests/installer_transaction_test.sh",
    "deploy/tests/release_launcher_root_test.sh",
    "deploy/tests/lifecycle_fake.sh",
    "deploy/tests/release_snapshot.py",
    "deploy/tests/restore_crash_driver.py",
}
BINARY_PATHS = {
    "release/artifacts/pgw-api",
    "release/artifacts/pgw-agent",
    "release/artifacts/pgw-fwd",
    "release/artifacts/pgw-ui",
    "release/artifacts/pgw-health",
    "release/artifacts/pgw-snapshot-crypt",
    "pgw-release-launcher",
}
PROOF_SUFFIXES = (
    "go-version.txt",
    "file.txt",
    "elf-header.txt",
    "elf-dynamic.txt",
)


class VerificationError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise VerificationError(message)


def open_clean_directory(path: str) -> int:
    absolute = os.path.abspath(path)
    if os.path.normpath(absolute) != absolute:
        fail("snapshot source path is not normalized")
    descriptor = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in (part for part in absolute.split(os.sep) if part):
            next_descriptor = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def source_identity(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def snapshot_tree(source: str, destination: str) -> None:
    if os.path.lexists(destination):
        fail("snapshot destination already exists")
    parent = os.path.dirname(os.path.abspath(destination))
    if not os.path.isdir(parent):
        fail("snapshot destination parent is missing")
    source_fd = open_clean_directory(source)
    os.mkdir(destination, 0o700)
    destination_fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    counters = {"files": 0, "bytes": 0}

    def copy_directory(src_fd: int, dst_fd: int, relative: str) -> None:
        before_info = os.fstat(src_fd)
        before_names = sorted(os.listdir(src_fd))
        if any(not name or name in (".", "..") or "/" in name or "\x00" in name for name in before_names):
            fail(f"invalid snapshot entry name below {relative or '.'}")
        for name in before_names:
            child_relative = f"{relative}/{name}" if relative else name
            listed = os.stat(name, dir_fd=src_fd, follow_symlinks=False)
            if stat.S_ISDIR(listed.st_mode):
                child_source = os.open(
                    name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=src_fd,
                )
                try:
                    opened = os.fstat(child_source)
                    if source_identity(opened) != source_identity(listed):
                        fail(f"directory changed during snapshot: {child_relative}")
                    os.mkdir(name, stat.S_IMODE(opened.st_mode), dir_fd=dst_fd)
                    child_destination = os.open(
                        name,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=dst_fd,
                    )
                    try:
                        copy_directory(child_source, child_destination, child_relative)
                        os.fsync(child_destination)
                    finally:
                        os.close(child_destination)
                finally:
                    os.close(child_source)
            elif stat.S_ISREG(listed.st_mode):
                counters["files"] += 1
                counters["bytes"] += listed.st_size
                if counters["files"] > MAX_FILES or counters["bytes"] > MAX_BYTES:
                    fail("release snapshot exceeds bounded file or byte budget")
                child_source = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=src_fd)
                try:
                    opened_before = os.fstat(child_source)
                    if source_identity(opened_before) != source_identity(listed):
                        fail(f"file changed before snapshot: {child_relative}")
                    child_destination = os.open(
                        name,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                        stat.S_IMODE(opened_before.st_mode),
                        dir_fd=dst_fd,
                    )
                    try:
                        remaining = opened_before.st_size
                        while remaining:
                            chunk = os.read(child_source, min(1024 * 1024, remaining))
                            if not chunk:
                                fail(f"short read during snapshot: {child_relative}")
                            view = memoryview(chunk)
                            while view:
                                written = os.write(child_destination, view)
                                view = view[written:]
                            remaining -= len(chunk)
                        if os.read(child_source, 1):
                            fail(f"file grew during snapshot: {child_relative}")
                        os.fchmod(child_destination, stat.S_IMODE(opened_before.st_mode))
                        os.fsync(child_destination)
                    finally:
                        os.close(child_destination)
                    if source_identity(os.fstat(child_source)) != source_identity(opened_before):
                        fail(f"file changed during snapshot: {child_relative}")
                finally:
                    os.close(child_source)
            else:
                fail(f"symlink or special node rejected: {child_relative}")
        if sorted(os.listdir(src_fd)) != before_names or source_identity(os.fstat(src_fd)) != source_identity(before_info):
            fail(f"directory changed during snapshot: {relative or '.'}")
        os.fsync(dst_fd)

    try:
        copy_directory(source_fd, destination_fd, "")
    except Exception:
        # The caller owns cleanup of an unpublished, incomplete snapshot.
        raise
    finally:
        os.close(destination_fd)
        os.close(source_fd)


def read_text_strict(path: Path, maximum: int = 1024 * 1024) -> list[str]:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
        fail(f"manifest is not a bounded regular file: {path.name}")
    payload = path.read_bytes()
    if not payload.endswith(b"\n") or b"\r" in payload or b"\x00" in payload:
        fail(f"manifest has invalid line encoding: {path.name}")
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError as exc:
        raise VerificationError(f"manifest is not ASCII: {path.name}") from exc
    lines = text.splitlines()
    if not lines or any(not line for line in lines):
        fail(f"manifest contains an empty line: {path.name}")
    return lines


def clean_relative_path(value: str) -> bool:
    return len(value) <= 256 and PATH_RE.fullmatch(value) is not None and all(
        component not in (".", "..") for component in value.split("/")
    )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_regular_tree(root: Path) -> None:
    count = 0
    total = 0
    for directory, directories, files in os.walk(root, followlinks=False):
        directories.sort()
        files.sort()
        for name in directories + files:
            path = Path(directory, name)
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                fail(f"snapshot contains symlink or special node: {path.relative_to(root)}")
            if stat.S_ISREG(info.st_mode):
                count += 1
                total += info.st_size
    if count > MAX_FILES or total > MAX_BYTES:
        fail("snapshot exceeds bounded file or byte budget")


def parse_trust(root: Path) -> tuple[str, str]:
    lines = read_text_strict(root / "release-trust.manifest", 4096)
    if len(lines) != 3 or lines[0] != "format pgw-trust-v1":
        fail("invalid trust manifest structure")
    release_fields: dict[str, str] = {}
    for line in lines[1:]:
        parts = line.split(" ")
        if len(parts) != 2 or parts[0] in release_fields:
            fail("duplicate or malformed trust manifest field")
        release_fields[parts[0]] = parts[1]
    if set(release_fields) != {"release_id", "manifest_sha256"}:
        fail("missing or extra trust manifest field")
    release_id = release_fields["release_id"]
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", release_id) is None:
        fail("invalid release ID")
    digest = release_fields["manifest_sha256"]
    if HEX_RE.fullmatch(digest) is None:
        fail("invalid trusted release manifest digest")
    return release_id, digest


def parse_release_manifest(root: Path, pinned_digest: str) -> dict[str, tuple[str, int]]:
    release_root = root / "release"
    manifest = release_root / "release.manifest"
    if sha256(manifest) != pinned_digest:
        fail("release trust digest does not bind the snapshotted manifest")
    lines = read_text_strict(manifest)
    if lines[0] != "format pgw-release-v1":
        fail("invalid release manifest header")
    entries: dict[str, tuple[str, int]] = {}
    for line in lines[1:]:
        parts = line.split(" ")
        if len(parts) != 4 or parts[0] != "file":
            fail("malformed release manifest entry")
        digest, mode_text, relative = parts[1:]
        if HEX_RE.fullmatch(digest) is None or mode_text not in ("0600", "0644", "0755"):
            fail("invalid release manifest digest or mode")
        if not clean_relative_path(relative) or relative in entries:
            fail("duplicate or unsafe release manifest path")
        entries[relative] = (digest, int(mode_text, 8))
    if set(entries) != RELEASE_PATHS:
        missing = sorted(RELEASE_PATHS - set(entries))
        extra = sorted(set(entries) - RELEASE_PATHS)
        fail(f"release manifest allowlist mismatch: missing={missing} extra={extra}")
    actual_paths = {
        path.relative_to(release_root).as_posix()
        for path in release_root.rglob("*")
        if path.is_file() and path.name != "release.manifest"
    }
    if actual_paths != set(entries):
        fail("release directory has missing or extra files")
    for relative, (expected_digest, expected_mode) in entries.items():
        path = release_root / relative
        info = path.lstat()
        required_mode = 0o755 if relative.startswith("artifacts/") or relative.endswith(".sh") else 0o644
        if expected_mode != required_mode:
            fail(f"release manifest declared an unexpected mode: {relative}")
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != required_mode:
            fail(f"release file type or mode mismatch: {relative}")
        if sha256(path) != expected_digest:
            fail(f"release file checksum mismatch: {relative}")
    return entries


def proof_digest(proof_root: Path, name: str) -> str:
    digest = hashlib.sha256()
    for suffix in PROOF_SUFFIXES:
        digest.update(suffix.encode("ascii"))
        digest.update(b"\x00")
        digest.update(sha256(proof_root / f"{name}.{suffix}").encode("ascii"))
        digest.update(b"\x00")
    return digest.hexdigest()


def parse_build_proof(root: Path, release_entries: dict[str, tuple[str, int]]) -> list[str]:
    lines = read_text_strict(root / "build-proof.manifest")
    if len(lines) != 9 or lines[0] != "format pgw-build-proof-v2":
        fail("invalid build proof header")
    module_parts = lines[1].split(" ")
    deterministic_parts = lines[2].split(" ")
    if (
        len(module_parts) != 2
        or module_parts[0] != "module_verify_sha256"
        or HEX_RE.fullmatch(module_parts[1]) is None
        or deterministic_parts != ["deterministic_builds", "2"]
    ):
        fail("invalid module or deterministic build proof")
    entries: dict[str, tuple[str, str]] = {}
    for line in lines[3:]:
        parts = line.split(" ")
        if len(parts) != 7 or parts[0] != "binary" or parts[3:6] != [
            "cgo=0",
            "dynamic=absent",
            "rebuild=identical",
        ]:
            fail("malformed build proof entry")
        digest, relative, proof_field = parts[1], parts[2], parts[6]
        if HEX_RE.fullmatch(digest) is None or not proof_field.startswith("proof_sha256="):
            fail("invalid build proof digest")
        proof = proof_field.removeprefix("proof_sha256=")
        if HEX_RE.fullmatch(proof) is None or relative in entries:
            fail("duplicate or malformed build proof entry")
        entries[relative] = (digest, proof)
    if set(entries) != BINARY_PATHS:
        fail("build proof binary allowlist mismatch")
    proof_root = root / "build-proof"
    expected_proof_files = {
        f"{Path(relative).name}.{suffix}"
        for relative in BINARY_PATHS
        for suffix in PROOF_SUFFIXES
    }
    expected_proof_files.add("go-mod-verify.txt")
    actual_proof_files = {
        path.relative_to(proof_root).as_posix() for path in proof_root.iterdir() if path.is_file()
    }
    if actual_proof_files != expected_proof_files:
        fail("build proof directory has missing or extra files")
    if sha256(proof_root / "go-mod-verify.txt") != module_parts[1]:
        fail("module verification proof checksum mismatch")
    report: list[str] = []
    for relative in sorted(entries):
        digest, expected_proof = entries[relative]
        binary = root / relative
        info = binary.lstat()
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o755:
            fail(f"binary type or mode mismatch: {relative}")
        if sha256(binary) != digest:
            fail(f"binary checksum mismatch: {relative}")
        if relative.startswith("release/"):
            manifest_relative = relative.removeprefix("release/")
            if release_entries.get(manifest_relative) != (digest, 0o755):
                fail(f"binary is not cross-bound to release manifest: {relative}")
        if proof_digest(proof_root, Path(relative).name) != expected_proof:
            fail(f"build proof checksum mismatch: {relative}")
        report.append(f"binary\t{relative}\t{digest}\t0755\tcgo0\tstatic\trebuild-identical")
    return report


def verify_ui_assets(root: Path) -> None:
    lines = read_text_strict(root / "release/deploy/ui-assets.sha256", 4096)
    entries: dict[str, str] = {}
    for line in lines:
        parts = line.split("  ")
        if len(parts) != 2 or HEX_RE.fullmatch(parts[0]) is None or parts[1] in entries:
            fail("malformed or duplicate UI asset manifest entry")
        relative = parts[1]
        if relative not in {
            "web/static/app.js",
            "web/static/styles.css",
            "web/static/login.js",
            "web/static/layout.css",
        }:
            fail("UI asset manifest has missing or extra path")
        entries[relative] = parts[0]
    if len(entries) != 4:
        fail("UI asset manifest is incomplete")
    for relative, expected in entries.items():
        if sha256(root / "release" / relative) != expected:
            fail(f"UI asset checksum mismatch: {relative}")


def verify_source_snapshot(root: Path) -> None:
    lines = read_text_strict(root / "source.manifest", 16 * 1024 * 1024)
    if len(lines) < 5 or lines[0] != "format pgw-source-snapshot-v1":
        fail("invalid source snapshot manifest header")
    fixed: dict[str, str] = {}
    for line in lines[1:4]:
        parts = line.split(" ")
        if len(parts) != 2 or parts[0] in fixed:
            fail("duplicate or malformed source identity field")
        fixed[parts[0]] = parts[1]
    if (
        set(fixed) != {"commit", "tree", "dirty"}
        or re.fullmatch(r"[0-9a-f]{40}", fixed["commit"]) is None
        or re.fullmatch(r"[0-9a-f]{40}", fixed["tree"]) is None
        or fixed["dirty"] not in ("true", "false")
    ):
        fail("invalid source snapshot identity")
    entries: dict[str, tuple[str, int]] = {}
    for line in lines[4:]:
        parts = line.split(" ")
        if len(parts) != 4 or parts[0] != "file":
            fail("malformed source snapshot entry")
        digest, mode_text, relative = parts[1:]
        if (
            HEX_RE.fullmatch(digest) is None
            or mode_text not in ("0644", "0755")
            or len(relative) > 512
            or SOURCE_PATH_RE.fullmatch(relative) is None
            or any(component in (".", "..") for component in relative.split("/"))
            or relative in entries
        ):
            fail("unsafe or duplicate source snapshot entry")
        entries[relative] = (digest, int(mode_text, 8))
    source_root = root / "source"
    actual = {
        path.relative_to(source_root).as_posix()
        for path in source_root.rglob("*")
        if path.is_file()
    }
    if actual != set(entries):
        fail("source snapshot has missing or extra files")
    for relative, (digest, mode) in entries.items():
        path = source_root / relative
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_IMODE(info.st_mode) != mode
            or sha256(path) != digest
        ):
            fail(f"source snapshot checksum or mode mismatch: {relative}")


def verify_snapshot(path: str) -> None:
    root = Path(path)
    verify_regular_tree(root)
    expected_top = {
        "release",
        "build-proof",
        "source",
        "source.manifest",
        "release-trust.manifest",
        "version.manifest",
        "migration.manifest",
        "build-proof.manifest",
        "pgw-release-launcher",
    }
    if {entry.name for entry in root.iterdir()} != expected_top:
        fail("assembly has missing or extra top-level entries")
    release_id, pinned_digest = parse_trust(root)
    verify_source_snapshot(root)
    release_entries = parse_release_manifest(root, pinned_digest)
    verify_ui_assets(root)
    report = parse_build_proof(root, release_entries)
    print(f"release_id\t{release_id}")
    print(f"release_manifest_sha256\t{pinned_digest}")
    print("snapshot_model\tdescriptor_first_regular_files_only")
    for line in report:
        print(line)


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    snapshot_parser = subparsers.add_parser("snapshot")
    snapshot_parser.add_argument("source")
    snapshot_parser.add_argument("destination")
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("snapshot")
    args = parser.parse_args()
    try:
        if args.command == "snapshot":
            snapshot_tree(args.source, args.destination)
        else:
            verify_snapshot(args.snapshot)
    except (OSError, VerificationError) as exc:
        print(f"release snapshot: {exc}", file=sys.stderr)
        return 65
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
