#!/usr/bin/env python3
"""Static oracle for candidate-code and production-attestor privilege separation."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
HANDOFF = ROOT / "deploy" / "trust" / "external-attestor-handoff.json"
REMOVED_SHELL_ENTRYPOINT = ROOT / "deploy" / "verify-release-attestation.sh"


def main() -> int:
    workflow_text = WORKFLOW.read_text(encoding="utf-8")
    lines = workflow_text.splitlines()
    job_starts = [
        (index, match.group(1))
        for index, line in enumerate(lines)
        if (match := re.fullmatch(r"  ([a-z][a-z0-9-]*):", line)) and match.group(1) not in {"push", "pull-request"}
    ]
    jobs: dict[str, str] = {}
    for position, (start, name) in enumerate(job_starts):
        end = job_starts[position + 1][0] if position + 1 < len(job_starts) else len(lines)
        jobs[name] = "\n".join(lines[start:end])
    assert jobs, "no CI jobs parsed"
    for name, job in jobs.items():
        executes_candidate = "run:" in job or "actions/checkout@" in job or "uses: ./" in job
        permission_match = re.search(r"(?m)^    permissions:\n((?:      [^\n]+\n?)*)", job)
        permissions = permission_match.group(1).strip().splitlines() if permission_match else []
        if executes_candidate:
            assert permissions == ["contents: read"], f"{name} has candidate code plus excess permissions"
            assert "secrets." not in job, f"{name} receives secret material"
        has_oidc = "id-token: write" in job or "attestations: write" in job
        if has_oidc:
            assert "run:" not in job, f"OIDC job {name} runs shell"
            assert "actions/checkout@" not in job and "uses: ./" not in job, (
                f"OIDC job {name} checks out or executes candidate code"
            )

    assert "actions/attest@" not in workflow_text, "candidate repository still issues an attestation"
    assert "id-token: write" not in workflow_text and "attestations: write" not in workflow_text
    handoff = json.loads(HANDOFF.read_text(encoding="utf-8"))
    assert handoff["schema"] == "pgw-external-attestor-handoff-v6"
    assert handoff["status"] == "BLOCKED_UNPROVISIONED"
    assert handoff["production_promotion_available"] is False
    assert handoff["required_external_orchestrator"]["checkout_candidate_repository"] is False
    assert handoff["required_external_orchestrator"]["execute_candidate_files"] is False
    assert handoff["required_external_orchestrator"]["evidence_repository_must_differ_from_candidate_and_attestor"] is True
    assert handoff["required_external_orchestrator"]["required_signer_certificate_trigger"] == "workflow_dispatch"
    assert handoff["required_external_orchestrator"]["required_candidate_event"] == "push"
    assert handoff["required_external_orchestrator"]["required_predicate_schema"] == "pgw-external-release-attestation-predicate-v2"
    assert handoff["required_promoter"]["installed_outside_candidate_repository"] is True
    assert handoff["required_promoter"]["promotion_reachable_only_via_native_entrypoint"] is True
    assert "direct_promote_requires_valid_native_pair" not in handoff["required_promoter"]
    assert handoff["required_promoter"]["input_modes"] == ["0400", "0440", "0444"]
    assert handoff["required_offline_sigstore"]["online_attestation_lookup"] is False
    assert handoff["required_offline_sigstore"]["required_flags"] == [
        "--bundle", "--custom-trusted-root", "--no-public-good"
    ]
    assert handoff["promotion_transaction"]["atomic_stage_required"] is True
    assert handoff["promotion_transaction"]["success_is_not_print_only"] is True
    runtime_lock = handoff["runtime_lock"]
    assert runtime_lock["path"] == "/run/pgw-release-trust/promotion.lock"
    assert runtime_lock["parent"] == "/run/pgw-release-trust"
    assert runtime_lock["parent_owner"] == "root:root"
    assert runtime_lock["parent_allowed_modes"] == ["0700", "0750", "0755"]
    assert runtime_lock["provision_parent_each_boot"] is True
    assert runtime_lock["file_owner"] == "root:root"
    assert runtime_lock["file_mode"] == "0600"
    assert runtime_lock["file_type"] == "regular"
    assert runtime_lock["file_size"] == 0
    assert runtime_lock["file_link_count"] == 1
    assert runtime_lock["system_run_lock_directory_forbidden"] is True
    entrypoint = handoff["required_native_entrypoint"]
    assert entrypoint["path"] == "/opt/pgw-release-trust/bin/verify-release-attestation"
    assert entrypoint["hardlink_to"] == "/opt/pgw-release-trust/bin/attestor"
    assert entrypoint["same_device_and_inode"] is True
    assert entrypoint["exact_link_count"] == 2
    assert entrypoint["symlink_or_copy_forbidden"] is True
    assert entrypoint["shell_interpreter_forbidden"] is True
    assert entrypoint["candidate_repository_entrypoint_file_forbidden"] is True
    assert entrypoint["single_reviewed_binary_asset"] == "attestor-linux-amd64"
    assert entrypoint["fail_closed_atomic_update_order"] == ["attestor", "verify-release-attestation"]
    assert entrypoint["execution_authority"] == "linux-kernel-at-execfn"
    assert entrypoint["execfn_source"] == "/proc/self/auxv:AT_EXECFN"
    assert entrypoint["execfn_must_equal_fixed_path"] is True
    assert entrypoint["execfn_exactly_one_and_auxv_terminated"] is True
    assert entrypoint["argv0_untrusted"] is True
    assert "argv0_must_equal_fixed_path" not in entrypoint
    assert entrypoint["proc_self_exe_same_inode"] is True
    assert entrypoint["relative_symlink_proc_fd_and_execveat_paths_forbidden"] is True
    assert entrypoint["bash_env_has_no_interpreter_surface"] is True
    assert entrypoint["post_verification_stdout"] == "byte-exact-canonical-pgw-promotion-result-v1-json"
    assert entrypoint["post_verification_stderr"] == "empty"
    assert entrypoint["authoritative_exit_codes"] == {
        "promoted": 0,
        "pre_commit_failed": 75,
        "commit_indeterminate": 76,
        "committed_durability_indeterminate": 77,
    }
    assert entrypoint["pre_verification_failure"] == "empty-stdout-sanitized-stderr-original-exit"
    assert not REMOVED_SHELL_ENTRYPOINT.exists(), "candidate repository ships a shell trust entrypoint"

    pins = set(handoff["required_deploy_policy"]["must_pin"])
    expected_pins = {
        "verifier_digest", "candidate_repository", "candidate_workflow", "signer_repository",
        "signer_workflow", "signer_ref", "signer_digest", "certificate_identity",
        "certificate_issuer", "predicate_type", "deny_self_hosted", "evidence_repository",
        "evidence_workflow", "evidence_ref", "evidence_sha", "evidence_run_attempt",
        "evidence_public_key_spki_sha256", "verifier_name", "verifier_version",
        "verifier_commit", "verifier_source_digest", "trusted_gh_sha256", "trusted_root_sha256",
    }
    assert pins == expected_pins

    def trigger_contract(signer_trigger: str, candidate_event: str) -> bool:
        return signer_trigger == "workflow_dispatch" and candidate_event == "push"

    assert trigger_contract("workflow_dispatch", "push")
    assert not trigger_contract("push", "push"), "signer trigger was confused with candidate event"
    assert not trigger_contract("workflow_dispatch", "workflow_dispatch"), "candidate event was widened"
    print("CI candidate privilege separation and unavailable external-attestor contract: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
