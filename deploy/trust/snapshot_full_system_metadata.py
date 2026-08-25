#!/usr/bin/env python3
"""Snapshot only bounded signed metadata before touching full-system raw evidence."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

LIMITS = {
    "full-system-attestation.manifest": 4096,
    "full-system-attestation.sig": 16 * 1024,
    "full-system-evidence.index": 8192,
}
EXPECTED = set(LIMITS) | {"raw"}


class MetadataError(Exception):
    pass


def snapshot(source: Path, destination: Path) -> None:
    if destination.exists():
        raise MetadataError("metadata destination already exists")
    source_fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    destination.mkdir(mode=0o700)
    try:
        before = os.fstat(source_fd)
        names = os.listdir(source_fd)
        if len(names) != len(set(names)) or set(names) != EXPECTED:
            raise MetadataError("full-system top-level allowlist mismatch")
        raw_info = os.stat("raw", dir_fd=source_fd, follow_symlinks=False)
        if not stat.S_ISDIR(raw_info.st_mode):
            raise MetadataError("raw evidence root must be a real directory")
        for name, limit in LIMITS.items():
            entry = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
            if not stat.S_ISREG(entry.st_mode) or entry.st_size <= 0 or entry.st_size > limit:
                raise MetadataError(f"metadata size/type policy rejected: {name}")
            source_file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=source_fd)
            try:
                opened_before = os.fstat(source_file_fd)
                if (entry.st_dev, entry.st_ino) != (opened_before.st_dev, opened_before.st_ino):
                    raise MetadataError(f"metadata replaced before read: {name}")
                data = bytearray()
                while chunk := os.read(source_file_fd, min(64 * 1024, limit + 1 - len(data))):
                    data.extend(chunk)
                    if len(data) > limit:
                        raise MetadataError(f"metadata exceeds read budget: {name}")
                opened_after = os.fstat(source_file_fd)
                stable = (
                    opened_before.st_dev, opened_before.st_ino, opened_before.st_size,
                    opened_before.st_mtime_ns, opened_before.st_ctime_ns,
                ) == (
                    opened_after.st_dev, opened_after.st_ino, opened_after.st_size,
                    opened_after.st_mtime_ns, opened_after.st_ctime_ns,
                )
                if not stable or len(data) != opened_before.st_size:
                    raise MetadataError(f"metadata changed during read: {name}")
            finally:
                os.close(source_file_fd)
            output = destination / name
            output.write_bytes(data)
            output.chmod(0o600)
        after = os.fstat(source_fd)
        if set(os.listdir(source_fd)) != EXPECTED or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise MetadataError("full-system metadata directory changed during snapshot")
    finally:
        os.close(source_fd)


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: snapshot_full_system_metadata.py SOURCE DESTINATION", file=sys.stderr)
        return 2
    try:
        snapshot(Path(sys.argv[1]), Path(sys.argv[2]))
    except (OSError, MetadataError) as error:
        print(f"full-system metadata snapshot rejected: {error}", file=sys.stderr)
        return 65
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
