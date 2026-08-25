#!/usr/bin/env python3
"""Negative oracles for descriptor-safe release snapshotting (Linux CI)."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "deploy" / "snapshot_release_tree.py"


def run(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-I", str(HELPER), *arguments],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    if os.name != "posix":
        print("release snapshot boundary test: SKIP (requires POSIX dirfd semantics)")
        return 0
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        source = root / "source"
        source.mkdir()
        (source / "plain").write_text("stable\n", encoding="utf-8")
        snapshot = root / "snapshot"
        manifest = root / "snapshot.manifest"
        require(run("snapshot", str(source), str(snapshot), str(manifest)).returncode == 0, "stable snapshot failed")
        require(run("verify", str(snapshot), str(manifest)).returncode == 0, "stable verify failed")
        (snapshot / "plain").write_text("tampered\n", encoding="utf-8")
        require(run("verify", str(snapshot), str(manifest)).returncode == 65, "tamper passed exact verify")

        symlink_source = root / "symlink-source"
        symlink_source.mkdir()
        (symlink_source / "target").write_text("target\n", encoding="utf-8")
        (symlink_source / "link").symlink_to("target")
        require(
            run("snapshot", str(symlink_source), str(root / "symlink-copy"), str(root / "symlink.manifest")).returncode == 65,
            "symlink passed snapshot",
        )

        fifo_source = root / "fifo-source"
        fifo_source.mkdir()
        os.mkfifo(fifo_source / "pipe")
        require(
            run("snapshot", str(fifo_source), str(root / "fifo-copy"), str(root / "fifo.manifest")).returncode == 65,
            "FIFO passed snapshot",
        )

        race_source = root / "race-source"
        race_source.mkdir()
        racing_file = race_source / "payload"
        with racing_file.open("wb") as handle:
            handle.truncate(64 * 1024 * 1024)
        stop = threading.Event()

        def mutate() -> None:
            value = 0
            with racing_file.open("r+b", buffering=0) as handle:
                while not stop.is_set():
                    handle.seek(0)
                    handle.write(bytes((value,)))
                    os.fsync(handle.fileno())
                    value ^= 1

        mutator = threading.Thread(target=mutate, daemon=True)
        mutator.start()
        try:
            raced = run("snapshot", str(race_source), str(root / "race-copy"), str(root / "race.manifest"))
        finally:
            stop.set()
            mutator.join(timeout=5)
        require(raced.returncode == 65, "concurrent source mutation passed snapshot")

        oversized = root / "oversized-evidence"
        raw = oversized / "full-system" / "raw"
        raw.mkdir(parents=True)
        huge_raw = raw / "network-capture.pcap"
        with huge_raw.open("wb") as handle:
            handle.truncate(64 * 1024 * 1024 + 1)
        oversized_copy = root / "oversized-copy"
        require(
            run(
                "snapshot", str(oversized), str(oversized_copy),
                str(root / "oversized.manifest"), "evidence",
            ).returncode == 65,
            "oversized raw evidence passed early snapshot budget",
        )
        require(
            not (oversized_copy / "full-system" / "raw" / "network-capture.pcap").exists(),
            "snapshot copied an over-limit raw evidence file before rejecting it",
        )

        wide = root / "wide-evidence"
        wide.mkdir()
        for index in range(257):
            (wide / f"d{index:03d}").mkdir()
        wide_copy = root / "wide-copy"
        require(
            run("snapshot", str(wide), str(wide_copy), str(root / "wide.manifest"), "evidence").returncode == 65,
            "wide empty-directory tree passed aggregate record budget",
        )
        require(not wide_copy.exists(), "wide rejected tree was materialized")

        path_heavy = root / "path-heavy-evidence"
        heavy_children = path_heavy / "widepaths"
        heavy_children.mkdir(parents=True)
        for index in range(255):
            (heavy_children / (f"p{index:03d}-" + "x" * 244)).mkdir()
        path_heavy_copy = root / "path-heavy-copy"
        require(
            run(
                "snapshot", str(path_heavy), str(path_heavy_copy),
                str(root / "path-heavy.manifest"), "evidence",
            ).returncode == 65,
            "aggregate path-heavy empty-directory tree passed budget",
        )
        require(not path_heavy_copy.exists(), "path-heavy rejected tree was materialized")

        deep = root / "deep-evidence"
        cursor = deep
        for index in range(9):
            cursor = cursor / f"d{index}"
        cursor.mkdir(parents=True)
        deep_copy = root / "deep-copy"
        require(
            run("snapshot", str(deep), str(deep_copy), str(root / "deep.manifest"), "evidence").returncode == 65,
            "deep empty-directory tree passed depth budget",
        )
        require(not deep_copy.exists(), "deep rejected tree was materialized")

    print("release snapshot symlink, FIFO, tamper, race, and no-materialization budget tests: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
