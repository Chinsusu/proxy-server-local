#!/usr/bin/env python3
"""Static contract for a self-managed candidate CI job."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


def main() -> int:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "actions/attest@" not in text
    assert "id-token: write" not in text and "attestations: write" not in text
    match = re.search(r"(?ms)^  candidate-release:\n(?P<body>.*?)(?=^  [a-zA-Z0-9_-]+:\n|\Z)", text)
    assert match is not None, "candidate-release job is missing"
    body = match.group("body")
    assert re.search(r"(?m)^    permissions:\n      contents: read$", body), "candidate job must be read-only"
    assert "deploy/build-release.sh --source-commit" in body, "candidate job does not build an exact commit"
    assert "deploy/finalize-release.sh" in body, "candidate job does not finalize the candidate"
    assert "pgw-self-managed-candidate-${{ github.sha }}" in body, "candidate job does not publish the selected artifact"
    assert "secrets." not in body, "candidate job receives secret material"
    print("CI self-managed candidate contract: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
