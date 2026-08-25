#!/usr/bin/python3
"""Static contracts for E2E evidence and blocking CI dependencies."""

from pathlib import Path
import re
import sys


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: evidence_contract_test.py REPOSITORY_ROOT")
    root = Path(sys.argv[1]).resolve()
    format_path = root / "test/e2e/EVIDENCE_FORMAT"
    raw_format = format_path.read_bytes()
    require(raw_format == b"pgw-wave1-e2e-v1\n", "canonical E2E format changed unexpectedly")

    producer = (root / "test/e2e/netns_legacy_web_only.sh").read_text(encoding="utf-8")
    consumer = (root / ".github/workflows/network-e2e.yml").read_text(encoding="utf-8")
    require('${SCRIPT_DIR}/EVIDENCE_FORMAT' in producer, "E2E producer does not load canonical format")
    require("printf 'format=%s\\n' \"${EVIDENCE_FORMAT}\"" in producer,
            "E2E producer does not publish the loaded format")
    require('expected_evidence_format="$(< test/e2e/EVIDENCE_FORMAT)"' in consumer,
            "E2E consumer does not load canonical format")
    require('product_manifest[format]:-}" == "$expected_evidence_format"' in consumer,
            "E2E consumer does not compare the canonical format")
    require("pgw-wave0-e2e-v1" not in consumer, "obsolete Wave 0 evidence format remains accepted")
    require("sudo /bin/bash test/e2e/ipv6_management_oracle_test.sh" in consumer,
            "focused IPv6 management oracle is not a Linux evidence gate")
    require(re.search(r"(?ms)uses: actions/checkout@[0-9a-f]{40}.*?^\s+persist-credentials: false$", consumer),
            "network E2E checkout retains repository credentials")

    ci = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    match = re.search(r"(?ms)^  candidate-release:\n(?P<body>.*?)(?=^  [a-zA-Z0-9_-]+:\n|\Z)", ci)
    require(match is not None, "CI candidate-release job is missing")
    body = match.group("body")
    needs = re.search(r"(?m)^    needs: \[(?P<items>[a-zA-Z0-9_, -]+)\]$", body)
    require(needs is not None, "CI candidate-release.needs is missing or malformed")
    actual = {item.strip() for item in needs.group("items").split(",")}
    expected = {"quality", "protected-systemd", "security", "test"}
    require(actual == expected, f"CI candidate-release.needs = {sorted(actual)}, want {sorted(expected)}")
    require(re.search(r"(?m)^    permissions:\n      contents: read$", body) is not None,
            "candidate-release permissions are not exactly contents:read")
    require("actions/attest@" not in ci and "id-token: write" not in ci and "attestations: write" not in ci,
            "candidate CI can still issue production attestations")
    require("pgw-candidate-diagnostic-${{ github.sha }}" in body,
            "candidate-release no longer uploads the blocked diagnostic candidate")
    require("finalize-release.sh --require-full-system" not in body,
            "candidate job claims authoritative full-system finalization")
    print("E2E format and CI dependency contracts: PASS")


if __name__ == "__main__":
    main()
