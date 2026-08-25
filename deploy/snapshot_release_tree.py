#!/usr/bin/env python3
"""Descriptor-safe release input snapshot and exact-tree verifier."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import sys
from pathlib import Path

SAFE_COMPONENT = re.compile(r"^[A-Za-z0-9._@+~-]+$")
DEFAULT_MAX_RECORDS = 200_000
DEFAULT_MAX_DEPTH = 64
DEFAULT_MAX_PATH_BYTES = 32 * 1024 * 1024
DEFAULT_MAX_BYTES = 2 * 1024 * 1024 * 1024
EVIDENCE_MAX_RECORDS = 256
EVIDENCE_MAX_DEPTH = 8
EVIDENCE_MAX_PATH_BYTES = 64 * 1024
EVIDENCE_MAX_BYTES = 272 * 1024 * 1024
EVIDENCE_ORDINARY_FILE_MAX = 8 * 1024 * 1024
RAW_FILE_MAX = 64 * 1024 * 1024
RAW_TOTAL_MAX = 256 * 1024 * 1024
METADATA_LIMITS = {
    "full-system/full-system-attestation.manifest": 4096,
    "full-system/full-system-attestation.sig": 16 * 1024,
    "full-system/full-system-evidence.index": 8192,
}


class SnapshotError(Exception):
    pass


def safe_names(
    directory_fd: int,
    max_names: int = DEFAULT_MAX_RECORDS,
    max_path_contribution: int = DEFAULT_MAX_PATH_BYTES,
    prefix: str = "",
) -> list[str]:
    names: list[str] = []
    contribution = 0
    with os.scandir(directory_fd) as entries:
        for entry in entries:
            if len(names) >= max_names:
                raise SnapshotError("directory entry budget exceeded")
            relative = f"{prefix}/{entry.name}" if prefix else entry.name
            contribution += len(os.fsencode(relative))
            if contribution > max_path_contribution:
                raise SnapshotError("directory aggregate path budget exceeded")
            names.append(entry.name)
    if len(names) != len(set(names)):
        raise SnapshotError("duplicate directory entry")
    for name in names:
        if name in ("", ".", "..") or not SAFE_COMPONENT.fullmatch(name):
            raise SnapshotError(f"unsafe path component: {name!r}")
    return sorted(names, key=os.fsencode)


def profile_limits(profile: str) -> tuple[int, int, int, int]:
    if profile == "evidence":
        return EVIDENCE_MAX_RECORDS, EVIDENCE_MAX_DEPTH, EVIDENCE_MAX_PATH_BYTES, EVIDENCE_MAX_BYTES
    if profile == "default":
        return DEFAULT_MAX_RECORDS, DEFAULT_MAX_DEPTH, DEFAULT_MAX_PATH_BYTES, DEFAULT_MAX_BYTES
    raise SnapshotError("unknown snapshot profile")


def account_entry(profile: str, relative: str, entry: os.stat_result, counters: dict[str, int]) -> int:
    max_records, max_depth, max_path_bytes, max_bytes = profile_limits(profile)
    encoded_path = os.fsencode(relative)
    depth = relative.count("/") + 1
    if counters["records"] + 1 > max_records:
        raise SnapshotError("snapshot record budget exceeded before materialization")
    if depth > max_depth:
        raise SnapshotError("snapshot depth budget exceeded before materialization")
    if counters["path_bytes"] + len(encoded_path) > max_path_bytes:
        raise SnapshotError("snapshot aggregate path budget exceeded before materialization")
    counters["records"] += 1
    counters["path_bytes"] += len(encoded_path)
    if stat.S_ISDIR(entry.st_mode):
        return 0
    if not stat.S_ISREG(entry.st_mode):
        raise SnapshotError(f"special node rejected: {relative}")
    file_limit = max_bytes
    if profile == "evidence":
        file_limit = METADATA_LIMITS.get(relative, EVIDENCE_ORDINARY_FILE_MAX)
        if relative.startswith("full-system/raw/"):
            file_limit = RAW_FILE_MAX
            if counters["raw_bytes"] + entry.st_size > RAW_TOTAL_MAX:
                raise SnapshotError("full-system raw evidence byte budget exceeded before materialization")
            counters["raw_bytes"] += entry.st_size
    if entry.st_size < 0 or entry.st_size > file_limit:
        raise SnapshotError(f"snapshot file exceeds early size policy: {relative}")
    if counters["bytes"] + entry.st_size > max_bytes:
        raise SnapshotError("snapshot byte budget exceeded before materialization")
    counters["files"] += 1
    counters["bytes"] += entry.st_size
    return file_limit


def digest_copy(source_fd: int, destination: Path, mode: int, byte_limit: int) -> tuple[str, int]:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    destination_fd = os.open(destination, flags, mode & 0o777)
    digest = hashlib.sha256()
    size = 0
    try:
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > byte_limit:
                raise SnapshotError("snapshot file byte budget exceeded")
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(destination_fd, view)
                view = view[written:]
        os.fsync(destination_fd)
        os.fchmod(destination_fd, mode & 0o777)
    finally:
        os.close(destination_fd)
    return digest.hexdigest(), size


def snapshot(source: Path, destination: Path, manifest: Path, profile: str = "default") -> None:
    if destination.exists() or manifest.exists():
        raise SnapshotError("snapshot outputs must not exist")
    max_records, _, max_path_bytes, _ = profile_limits(profile)
    source_fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    records: list[tuple[str, str, int, int, str]] = []
    preflight = {"records": 0, "path_bytes": 0, "files": 0, "bytes": 0, "raw_bytes": 0}

    def inspect(directory_fd: int, prefix: str) -> None:
        before = os.fstat(directory_fd)
        remaining = max_records - preflight["records"]
        remaining_paths = max_path_bytes - preflight["path_bytes"]
        names = safe_names(directory_fd, remaining, remaining_paths, prefix)
        for name in names:
            relative = f"{prefix}/{name}" if prefix else name
            entry = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            account_entry(profile, relative, entry, preflight)
            if stat.S_ISDIR(entry.st_mode):
                child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
                try:
                    opened = os.fstat(child_fd)
                    if (entry.st_dev, entry.st_ino) != (opened.st_dev, opened.st_ino):
                        raise SnapshotError(f"directory replaced during preflight: {relative}")
                    inspect(child_fd, relative)
                finally:
                    os.close(child_fd)
        after = os.fstat(directory_fd)
        if names != safe_names(directory_fd, max_records, max_path_bytes, prefix) or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise SnapshotError(f"directory changed during preflight: {prefix or '.'}")

    copied = {"records": 0, "path_bytes": 0, "files": 0, "bytes": 0, "raw_bytes": 0}

    def walk(directory_fd: int, output: Path, prefix: str) -> None:
        before = os.fstat(directory_fd)
        names = safe_names(
            directory_fd, max_records - copied["records"],
            max_path_bytes - copied["path_bytes"], prefix,
        )
        for name in names:
            relative = f"{prefix}/{name}" if prefix else name
            entry = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            file_limit = account_entry(profile, relative, entry, copied)
            if stat.S_ISDIR(entry.st_mode):
                child_fd = os.open(
                    name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=directory_fd,
                )
                try:
                    opened = os.fstat(child_fd)
                    if (entry.st_dev, entry.st_ino) != (opened.st_dev, opened.st_ino):
                        raise SnapshotError(f"directory replaced during snapshot: {relative}")
                    child_output = output / name
                    child_output.mkdir(mode=entry.st_mode & 0o777)
                    os.chmod(child_output, entry.st_mode & 0o777)
                    records.append(("dir", "-", entry.st_mode & 0o777, 0, relative))
                    walk(child_fd, child_output, relative)
                finally:
                    os.close(child_fd)
            elif stat.S_ISREG(entry.st_mode):
                source_file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
                try:
                    opened_before = os.fstat(source_file_fd)
                    if (entry.st_dev, entry.st_ino) != (opened_before.st_dev, opened_before.st_ino):
                        raise SnapshotError(f"file replaced during snapshot: {relative}")
                    if opened_before.st_size != entry.st_size:
                        raise SnapshotError(f"file size changed after preflight: {relative}")
                    digest, size = digest_copy(source_file_fd, output / name, entry.st_mode, file_limit)
                    opened_after = os.fstat(source_file_fd)
                    stable = (
                        opened_before.st_dev,
                        opened_before.st_ino,
                        opened_before.st_size,
                        opened_before.st_mtime_ns,
                        opened_before.st_ctime_ns,
                    ) == (
                        opened_after.st_dev,
                        opened_after.st_ino,
                        opened_after.st_size,
                        opened_after.st_mtime_ns,
                        opened_after.st_ctime_ns,
                    )
                    if not stable or size != opened_before.st_size:
                        raise SnapshotError(f"file changed during snapshot: {relative}")
                finally:
                    os.close(source_file_fd)
                records.append(("file", digest, entry.st_mode & 0o777, size, relative))
        after_names = safe_names(directory_fd, max_records, max_path_bytes, prefix)
        after = os.fstat(directory_fd)
        if names != after_names or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise SnapshotError(f"directory changed during snapshot: {prefix or '.'}")

    try:
        # No output directory exists until the complete tree passes entry,
        # depth, aggregate-path and stat-size budgets.
        inspect(source_fd, "")
        destination.mkdir(mode=0o700)
        walk(source_fd, destination, "")
    finally:
        os.close(source_fd)
    if copied != preflight:
        raise SnapshotError("source resource accounting changed after preflight")

    with manifest.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write("format pgw-tree-snapshot-v2\n")
        handle.write(f"profile {profile}\n")
        handle.write(f"record_count {copied['records']}\n")
        handle.write(f"path_byte_count {copied['path_bytes']}\n")
        handle.write(f"file_count {copied['files']}\n")
        handle.write(f"byte_count {copied['bytes']}\n")
        for kind, digest, mode, size, relative in sorted(records, key=lambda r: os.fsencode(r[4])):
            handle.write(f"{kind} {digest} 0{mode:03o} {size} {relative}\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(manifest, 0o600)


def parse_manifest(manifest: Path) -> tuple[str, dict[str, int], dict[str, tuple[str, str, int, int]]]:
    info = manifest.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > 64 * 1024 * 1024:
        raise SnapshotError("snapshot manifest exceeds size policy")
    lines = manifest.read_text(encoding="utf-8").splitlines()
    if len(lines) < 6 or len(lines) > DEFAULT_MAX_RECORDS + 6 or lines[0] != "format pgw-tree-snapshot-v2":
        raise SnapshotError("invalid snapshot manifest header")
    if lines[1] not in ("profile default", "profile evidence"):
        raise SnapshotError("invalid snapshot profile")
    profile = lines[1].split()[1]
    header_keys = ("record_count", "path_byte_count", "file_count", "byte_count")
    declared: dict[str, int] = {}
    for offset, key in enumerate(header_keys, start=2):
        if not re.fullmatch(rf"{key} (0|[1-9][0-9]*)", lines[offset]):
            raise SnapshotError(f"invalid snapshot {key}")
        declared[key] = int(lines[offset].split()[1])
    max_records, _, max_path_bytes, max_bytes = profile_limits(profile)
    if (declared["record_count"] > max_records or declared["path_byte_count"] > max_path_bytes
            or declared["file_count"] > declared["record_count"] or declared["byte_count"] > max_bytes):
        raise SnapshotError("declared snapshot resource budget exceeded")
    records: dict[str, tuple[str, str, int, int]] = {}
    record_re = re.compile(
        r"(file|dir) (-|[0-9a-f]{64}) (0[0-7]{3}) (0|[1-9][0-9]*) "
        r"([A-Za-z0-9._@+~-]+(?:/[A-Za-z0-9._@+~-]+)*)"
    )
    for line in lines[6:]:
        match = record_re.fullmatch(line)
        if not match:
            raise SnapshotError("malformed snapshot record")
        kind, digest, mode, size, relative = match.groups()
        if relative in records or any(part in (".", "..") for part in relative.split("/")):
            raise SnapshotError("duplicate or traversing snapshot path")
        if (kind == "file") != (digest != "-") or (kind == "dir" and size != "0"):
            raise SnapshotError("invalid snapshot record fields")
        records[relative] = (kind, digest, int(mode, 8), int(size))
    if len(records) != declared["record_count"]:
        raise SnapshotError("snapshot record count mismatch")
    if sum(len(os.fsencode(relative)) for relative in records) != declared["path_byte_count"]:
        raise SnapshotError("snapshot path-byte count mismatch")
    return profile, declared, records


def verify(tree: Path, manifest: Path) -> None:
    profile, declared, records = parse_manifest(manifest)
    actual: dict[str, tuple[str, str, int, int]] = {}
    counters = {"records": 0, "path_bytes": 0, "files": 0, "bytes": 0, "raw_bytes": 0}
    max_records, _, max_path_bytes, _ = profile_limits(profile)
    root_fd = os.open(tree, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)

    def walk(directory_fd: int, prefix: str) -> None:
        for name in safe_names(
            directory_fd, max_records - counters["records"],
            max_path_bytes - counters["path_bytes"], prefix,
        ):
            relative = f"{prefix}/{name}" if prefix else name
            entry = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            account_entry(profile, relative, entry, counters)
            if stat.S_ISDIR(entry.st_mode):
                actual[relative] = ("dir", "-", entry.st_mode & 0o777, 0)
                child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
                try:
                    walk(child_fd, relative)
                finally:
                    os.close(child_fd)
            elif stat.S_ISREG(entry.st_mode):
                file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
                digest = hashlib.sha256()
                size = 0
                try:
                    while True:
                        chunk = os.read(file_fd, 1024 * 1024)
                        if not chunk:
                            break
                        digest.update(chunk)
                        size += len(chunk)
                finally:
                    os.close(file_fd)
                actual[relative] = ("file", digest.hexdigest(), entry.st_mode & 0o777, size)
            else:
                raise SnapshotError(f"special node rejected during verify: {relative}")

    try:
        walk(root_fd, "")
    finally:
        os.close(root_fd)
    if actual != records:
        missing = sorted(set(records) - set(actual))
        extra = sorted(set(actual) - set(records))
        changed = sorted(path for path in set(actual) & set(records) if actual[path] != records[path])
        raise SnapshotError(f"snapshot tree mismatch missing={missing[:3]} extra={extra[:3]} changed={changed[:3]}")
    files = [record for record in actual.values() if record[0] == "file"]
    if (counters["records"] != declared["record_count"]
            or counters["path_bytes"] != declared["path_byte_count"]
            or len(files) != declared["file_count"]
            or sum(record[3] for record in files) != declared["byte_count"]):
        raise SnapshotError("snapshot totals mismatch")


def main() -> int:
    try:
        if len(sys.argv) in (5, 6) and sys.argv[1] == "snapshot":
            profile = sys.argv[5] if len(sys.argv) == 6 else "default"
            snapshot(Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]), profile)
        elif len(sys.argv) == 4 and sys.argv[1] == "verify":
            verify(Path(sys.argv[2]), Path(sys.argv[3]))
        else:
            print("usage: snapshot_release_tree.py snapshot SOURCE DEST MANIFEST [default|evidence] | verify TREE MANIFEST", file=sys.stderr)
            return 2
    except (OSError, UnicodeError, SnapshotError) as error:
        print(f"release snapshot rejected: {error}", file=sys.stderr)
        return 65
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
