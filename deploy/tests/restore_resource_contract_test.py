#!/usr/bin/python3
"""Deterministic schema/resource-bound tests; privileged fd tests live in shell."""

import copy
import importlib.util
import json
import os
import pathlib
import stat
import tempfile
import types
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("pgw_restore_contract", ROOT / "deploy/restore_snapshot.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def directory(path="root"):
    return {"path": path, "type": "dir", "mode": 0o700, "uid": 0, "gid": 0}


def regular(path, size=0):
    return {
        "path": path,
        "type": "file",
        "mode": 0o600,
        "uid": 0,
        "gid": 0,
        "size": size,
        "sha256": "0" * 64,
    }


def symlink(path, target):
    return {
        "path": path,
        "type": "symlink",
        "mode": 0o777,
        "uid": 0,
        "gid": 0,
        "target": target,
    }


def document(records=None):
    return {
        "version": MODULE.METADATA_VERSION,
        "limits": copy.deepcopy(MODULE.RESOURCE_LIMITS),
        "roots": ["/root"],
        "records": records or [directory()],
    }


def expect_reason(reason, payload):
    with tempfile.TemporaryDirectory() as temporary:
        target = pathlib.Path(temporary, "metadata.json")
        target.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
        try:
            MODULE.load_metadata(str(target))
        except SystemExit as error:
            assert str(error) == reason, (reason, str(error))
        else:
            raise AssertionError("resource contract unexpectedly accepted: " + reason)


def expect_call_reason(reason, action):
    try:
        action()
    except SystemExit as error:
        assert str(error) == reason, (reason, str(error))
    else:
        raise AssertionError("resource contract unexpectedly accepted: " + reason)


with tempfile.TemporaryDirectory() as temporary:
    target = pathlib.Path(temporary, "metadata.json")
    target.write_text(json.dumps(document(), separators=(",", ":")), encoding="utf-8")
    roots, records = MODULE.load_metadata(str(target))
    assert roots == ["/root"] and list(records) == ["root"]
    assert isinstance(records, MODULE.RecordMap)
    assert records.children == {}

bad_contract = document()
bad_contract["limits"]["max_records"] += 1
expect_reason("snapshot resource contract mismatch", bad_contract)

expect_reason(
    "resource_limit: max_records",
    document([directory()] + [regular(f"root/f{index:04d}") for index in range(4096)]),
)

deep_path = "root/" + "/".join("a" for _ in range(MODULE.RESOURCE_LIMITS["max_depth"]))
expect_reason("resource_limit: max_depth", document([directory(), regular(deep_path)]))

expect_reason(
    "resource_limit: max_member_bytes",
    document([directory(), regular("root/" + "m" * 256)]),
)

expect_reason(
    "snapshot metadata path is not canonical",
    document([directory(), regular("root/bad\x00path")]),
)

expect_reason(
    "invalid snapshot symlink target",
    document([directory(), symlink("root/link", "target\x00suffix")]),
)

expect_call_reason(
    "snapshot logical root is not canonical",
    lambda: MODULE.clean_logical_path("/root\x00suffix"),
)

long_path = "root/" + "/".join("p" * 250 for _ in range(17))
expect_reason("resource_limit: max_path_bytes", document([directory(), regular(long_path)]))

expect_reason(
    "resource_limit: max_file_bytes",
    document([directory(), regular("root/large", MODULE.RESOURCE_LIMITS["max_file_bytes"] + 1)]),
)

expect_reason(
    "resource_limit: max_aggregate_file_bytes",
    document([directory()] + [
        regular(f"root/aggregate-{index}", MODULE.RESOURCE_LIMITS["max_file_bytes"])
        for index in range(5)
    ]),
)

member_records = [directory()]
for index in range(2200):
    suffix = f"-{index:04d}"
    member_records.append(regular("root/" + "m" * (240 - len(suffix)) + suffix))
expect_reason("resource_limit: max_total_member_bytes", document(member_records))

prefix = "/".join("p" * 120 for _ in range(30))
path_records = [directory()]
for index in range(2400):
    path_records.append(regular(f"root/{prefix}/{index:04d}"))
expect_reason("resource_limit: max_total_path_bytes", document(path_records))

with tempfile.TemporaryDirectory() as temporary:
    target = pathlib.Path(temporary, "metadata.json")
    with target.open("wb") as handle:
        handle.truncate(MODULE.MAX_METADATA_BYTES + 1)
    try:
        MODULE.load_metadata(str(target))
    except SystemExit as error:
        assert str(error) == "resource_limit: metadata_bytes"
    else:
        raise AssertionError("oversized metadata was accepted")

with tempfile.TemporaryDirectory() as temporary:
    manifest = pathlib.Path(temporary, "manifest")
    with manifest.open("wb") as handle:
        handle.truncate(MODULE.MAX_MANIFEST_BYTES + 1)
    expect_call_reason(
        "resource_limit: manifest_bytes",
        lambda: MODULE.load_manifest(str(manifest)),
    )

# Capture rejects traversal and file allocation before reading/copying the
# offending object.  This exercises the same production function with a
# portable destination so the contract runs on both Linux and Windows CI.
with tempfile.TemporaryDirectory() as temporary:
    source = pathlib.Path(temporary, "source")
    source.mkdir()
    cursor = source
    for index in range(MODULE.RESOURCE_LIMITS["max_depth"]):
        cursor = cursor / f"d{index}"
        cursor.mkdir()
    (cursor / "state").write_text("too deep", encoding="utf-8")
    target = pathlib.Path(temporary, "target")
    expect_call_reason(
        "resource_limit: max_depth",
        lambda: MODULE.restore_portable(
            "present", str(source), str(target), MODULE.ResourceBudget(), "root"
        ),
    )

with tempfile.TemporaryDirectory() as temporary:
    source = pathlib.Path(temporary, "large")
    source.write_bytes(b"fixture")
    target = pathlib.Path(temporary, "target")
    real_lstat = os.lstat

    def oversized_lstat(path):
        if os.fspath(path) == str(source):
            actual = real_lstat(path)
            return types.SimpleNamespace(**{
                name: (MODULE.RESOURCE_LIMITS["max_file_bytes"] + 1
                       if name == "st_size" else getattr(actual, name))
                for name in (
                    "st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_size",
                    "st_nlink", "st_mtime_ns", "st_ctime_ns",
                )
            })
        return real_lstat(path)

    oversized = oversized_lstat(str(source))
    with (mock.patch.object(MODULE.os, "lstat", side_effect=oversized_lstat),
          mock.patch.object(MODULE.os, "fstat", return_value=oversized)):
        expect_call_reason(
            "resource_limit: max_file_bytes",
            lambda: MODULE.restore_portable(
                "present", str(source), str(target), MODULE.ResourceBudget(), "root"
            ),
        )
    assert not target.exists(), "oversized capture allocated a destination"

with tempfile.TemporaryDirectory() as temporary:
    root = pathlib.Path(temporary)
    system = root / "system"
    snapshot = root / "snapshot"
    (system / "one").mkdir(parents=True)
    (system / "two").mkdir(parents=True)
    (system / "one" / "state").write_bytes(b"1234")
    (system / "two" / "state").write_bytes(b"5678")
    (snapshot / "files").mkdir(parents=True)
    (snapshot / "manifest").write_text(
        "present\t/one/state\npresent\t/two/state\n", encoding="utf-8"
    )
    prior_limit = MODULE.RESOURCE_LIMITS["max_aggregate_file_bytes"]
    MODULE.RESOURCE_LIMITS["max_aggregate_file_bytes"] = 7
    try:
        expect_call_reason(
            "resource_limit: max_aggregate_file_bytes",
            lambda: MODULE.capture_all_portable(str(snapshot), str(system)),
        )
    finally:
        MODULE.RESOURCE_LIMITS["max_aggregate_file_bytes"] = prior_limit
    assert not any((snapshot / "files").iterdir()), "global capture left partial payload"

# The publication order is contractual: complete ciphertext/receipt verification
# precedes both the checksum seal and HMAC/ready publication. Plaintext capture
# is intentionally absent from the backup lifecycle.
installer = (ROOT / "deploy/install-pgw.sh").read_text(encoding="utf-8")
function = installer.split("write_snapshot_metadata() {", 1)[1].split("\n}\n", 1)[0]
verify_at = function.index('verify_snapshot_payload || die "rollback ciphertext payload self-check failed"')
checksum_at = function.index('checksum_temporary="${backup_dir}/.snapshot.sha256.tmp"')
hmac_at = function.index('snapshot_auth create "${backup_dir}"')
assert verify_at < checksum_at < hmac_at

print("restore resource contract tests: PASS")
