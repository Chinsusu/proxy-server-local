#!/usr/bin/env python3
"""Unit and negative tests for the canonical full-system evidence parser."""

from __future__ import annotations

import hashlib
import importlib.util
import shutil
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "deploy" / "trust" / "verify_full_system_evidence.py"
SPEC = importlib.util.spec_from_file_location("verify_full_system_evidence", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

RELEASE_ID = "test-v3"
RELEASE_MANIFEST = "a" * 64
SOURCE_SHA = "b" * 40
RUN_ID = "12345"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def create_fixture(root: Path) -> None:
    raw = root / "raw"
    raw.mkdir(parents=True)
    for index, relative in enumerate(MODULE.RAW_FILES):
        path = root / relative
        path.write_bytes(f"raw-evidence-{index}\n".encode())
    records = {
        relative: (sha(root / relative), (root / relative).stat().st_size)
        for relative in MODULE.RAW_FILES
    }
    index_lines = [
        "format pgw-full-system-evidence-index-v1",
        f"release_id {RELEASE_ID}",
        f"release_manifest_sha256 {RELEASE_MANIFEST}",
        f"source_commit {SOURCE_SHA}",
        "producer protected-ci",
        f"run_id {RUN_ID}",
        f"file_count {len(MODULE.RAW_FILES)}",
    ]
    for relative in sorted(records):
        digest, size = records[relative]
        index_lines.append(f"file {digest} {size} {relative}")
    index = root / "full-system-evidence.index"
    index.write_text("\n".join(index_lines) + "\n", encoding="utf-8", newline="\n")
    manifest_lines = [
        "format pgw-full-system-attestation-v2",
        f"release_id {RELEASE_ID}",
        f"release_manifest_sha256 {RELEASE_MANIFEST}",
        f"source_commit {SOURCE_SHA}",
        "transaction_model full_system",
        "isolation vm-or-dedicated-rootfs",
        "private_namespaces user,pid,mount,network,ipc,uts",
        "credential_free true",
        "binary_count 6",
        "ui_assets PASS",
        "units_policy_tmpfiles PASS",
        "credential_transition PASS",
        "database_migration_integrity PASS",
        "base_firewall_sysctl_services PASS",
        "production_root_lifecycle PASS",
        "rollback PASS",
        "fail_close PASS",
        "producer protected-ci",
        f"run_id {RUN_ID}",
        f"evidence_index_sha256 {sha(index)}",
        f"raw_payload_sha256 {MODULE.payload_digest(records)}",
    ]
    (root / "full-system-attestation.manifest").write_text(
        "\n".join(manifest_lines) + "\n", encoding="utf-8", newline="\n"
    )
    (root / "full-system-attestation.sig").write_bytes(b"S" * 64)


def rejected(root: Path, release_manifest: str = RELEASE_MANIFEST, source_sha: str = SOURCE_SHA, run_id: str = RUN_ID) -> bool:
    try:
        MODULE.verify(root, RELEASE_ID, release_manifest, source_sha, run_id)
    except MODULE.EvidenceError:
        return True
    return False


def main() -> int:
    with tempfile.TemporaryDirectory() as temporary:
        base = Path(temporary) / "valid"
        create_fixture(base)
        MODULE.verify(base, RELEASE_ID, RELEASE_MANIFEST, SOURCE_SHA, RUN_ID)

        for scenario in ("missing", "extra", "tampered", "reordered"):
            fixture = Path(temporary) / scenario
            shutil.copytree(base, fixture)
            if scenario == "missing":
                (fixture / MODULE.RAW_FILES[0]).unlink()
            elif scenario == "extra":
                (fixture / "raw" / "unapproved.txt").write_text("extra\n", encoding="utf-8")
            else:
                if scenario == "tampered":
                    with (fixture / MODULE.RAW_FILES[1]).open("ab") as handle:
                        handle.write(b"tamper")
                else:
                    index = fixture / "full-system-evidence.index"
                    index_lines = index.read_text(encoding="utf-8").splitlines()
                    index_lines[-1], index_lines[-2] = index_lines[-2], index_lines[-1]
                    index.write_text("\n".join(index_lines) + "\n", encoding="utf-8", newline="\n")
            assert rejected(fixture), f"{scenario} raw evidence passed"

        assert rejected(base, release_manifest="c" * 64), "wrong release manifest passed"
        assert rejected(base, source_sha="d" * 40), "wrong source SHA passed"
        assert rejected(base, run_id="54321"), "wrong protected run ID passed"

        for name, limit in (
            ("full-system-attestation.manifest", MODULE.MAX_MANIFEST_BYTES),
            ("full-system-evidence.index", MODULE.MAX_INDEX_BYTES),
            ("full-system-attestation.sig", MODULE.MAX_SIGNATURE_BYTES),
        ):
            fixture = Path(temporary) / f"oversized-{name}"
            shutil.copytree(base, fixture)
            with (fixture / name).open("wb") as handle:
                handle.truncate(limit + 1)
            assert rejected(fixture), f"oversized {name} passed"

    print("full-system evidence exact-set and identity negative tests: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
