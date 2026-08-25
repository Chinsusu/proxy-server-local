#!/usr/bin/python3
"""Test-only crash injector around the production restore implementation.

This file is reachable only through the validated non-root installer harness.
The production installer and release manifest never install or execute it.
"""

import importlib.util
import json
import os
import re
import signal
import sys


def fail(message):
    raise SystemExit(message)


def terminate():
    # The Python helper is exec'd by the installer harness. Kill that Bash
    # process first so its EXIT rollback trap cannot run, then kill the helper.
    os.kill(os.getppid(), signal.SIGKILL)
    os.kill(os.getpid(), signal.SIGKILL)


def load_restore(path):
    spec = importlib.util.spec_from_file_location("pgw_restore_snapshot_under_test", path)
    if spec is None or spec.loader is None:
        fail("cannot load production restore helper")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def publish_hook_marker(root, state, logical, point, residue, metadata, operation_id, nonce):
    marker = os.path.join(root, "restore-hook-reached.json")
    temporary = os.path.join(root, ".restore-hook-reached.tmp." + nonce)
    if os.path.lexists(marker) or os.path.lexists(temporary):
        fail("stale restore hook marker")
    payload = json.dumps(
        {
            "version": 1,
            "state": state,
            "logical": logical,
            "point": point,
            "residue": residue,
            "metadata": metadata,
            "operation_id": operation_id,
            "nonce": nonce,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8") + b"\n"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    try:
        view = memoryview(payload)
        while view:
            view = view[os.write(descriptor, view):]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    # link() is an atomic no-replace publication. A stale/precreated final
    # marker makes the test fail rather than allowing a false positive.
    os.link(temporary, marker, follow_symlinks=False)
    os.unlink(temporary)
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def main():
    if len(sys.argv) != 8:
        fail("usage: restore_crash_driver.py HELPER STATE SOURCE TARGET METADATA LOGICAL UID")
    helper, state, source, target, metadata, logical, expected_uid = sys.argv[1:]
    if os.geteuid() == 0:
        fail("restore crash driver is unavailable to root")
    fixture_root = os.environ["PGW_FAKE_ROOT"]
    control = os.path.join(fixture_root, "restore-crash-control")
    with open(control, encoding="utf-8") as handle:
        expected_state, expected_logical, point, nonce, expected_operation_id = (
            handle.read().strip().split("\t")
        )
    if (state, logical) != (expected_state, expected_logical):
        fail("crash driver invoked for unexpected restore root")
    if point not in ("partial_stage", "post_exchange", "mid_cleanup"):
        fail("invalid restore crash point")
    if re.fullmatch(r"[0-9a-f]{64}", nonce) is None:
        fail("invalid restore crash nonce")
    if re.fullmatch(r"[0-9a-f]{64}", expected_operation_id) is None:
        fail("invalid restore crash operation id")
    if os.environ.get("PGW_RESTORE_CRASH_OPERATION_ID") != expected_operation_id:
        fail("restore crash operation id does not match validated control")
    if os.name != "posix":
        fail("descriptor-bound crash driver requires POSIX")

    restore = load_restore(helper)
    residue_kind = "stage" if state == "present" else "tomb"
    residue = restore.deterministic_restore_name(metadata, logical, residue_kind)
    # The production recovery journal is intentionally derived from the
    # HMAC-covered ciphertext payload manifest before the private /run stage
    # exists.  The harness has already computed and validated that identity;
    # stage metadata remains used only to identify deterministic restore
    # residue.
    operation_id = expected_operation_id

    def reached():
        publish_hook_marker(
            fixture_root, state, logical, point, residue, metadata, operation_id, nonce
        )

    if point == "partial_stage":
        if state == "present":
            original_copy = restore.copy_node
            calls = 0

            def crash_during_stage(*args, **kwargs):
                nonlocal calls
                calls += 1
                this_call = calls
                result = original_copy(*args, **kwargs)
                # Call one is the logical root. Killing after its first child
                # leaves a durable incomplete stage tree before exchange.
                if this_call == 2:
                    reached()
                    terminate()
                return result

            restore.copy_node = crash_during_stage
        else:
            original_rename = restore.os.rename

            def crash_before_absent_rename(*args, **kwargs):
                if len(args) >= 2 and args[1] == residue:
                    reached()
                    terminate()
                return original_rename(*args, **kwargs)

            restore.os.rename = crash_before_absent_rename

    elif point == "post_exchange":
        if state == "present":
            original_exchange = restore.exchange

            def crash_after_exchange(*args, **kwargs):
                original_exchange(*args, **kwargs)
                reached()
                terminate()

            restore.exchange = crash_after_exchange
        else:
            original_rename = restore.os.rename

            def crash_after_absent_rename(*args, **kwargs):
                result = original_rename(*args, **kwargs)
                if len(args) >= 2 and args[1] == residue:
                    reached()
                    terminate()
                return result

            restore.os.rename = crash_after_absent_rename

    else:
        original_remove = restore.remove_at
        cleanup_started = False
        cleanup_calls = 0

        def crash_during_cleanup(parent, name):
            nonlocal cleanup_started, cleanup_calls
            if name == residue:
                cleanup_started = True
            if cleanup_started:
                cleanup_calls += 1
                this_call = cleanup_calls
            else:
                this_call = 0
            result = original_remove(parent, name)
            # Root removal is call one. Kill after one child is removed so the
            # deterministic residue is present but partially cleaned.
            if this_call == 2:
                reached()
                terminate()
            return result

        restore.remove_at = crash_during_cleanup

    restore.restore_posix(state, source, target, metadata, logical, int(expected_uid))
    fail("restore crash point was not reached")


if __name__ == "__main__":
    main()
