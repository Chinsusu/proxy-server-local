#!/usr/bin/python3
"""Byte-pinned structural lint only; JavaScript semantics are tested by Node."""

import hashlib
import sys


PINNED_SHA256 = "36304260b626f196a4e3eecbe8480c3b0857121cdcec4172416e0b6f4dfa399c"


def deny_unless(condition, message):
    if not condition:
        raise SystemExit(message)


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: polkit_rule_test.py RULE")
    raw = open(sys.argv[1], "rb").read()
    deny_unless(b"\x00" not in raw and b"\r" not in raw, "unsafe rule encoding")
    deny_unless(hashlib.sha256(raw).hexdigest() == PINNED_SHA256,
                "polkit rule bytes differ from the reviewed structural pin")
    source = raw.decode("utf-8")
    required = (
        'action.id !== "org.freedesktop.systemd1.manage-units"',
        'subject.user !== "pgw-agent"',
        '["start", "stop", "restart"].indexOf(verb) === -1',
        r'/^pgw-fwd@([0-9]+)\.service$/.exec(unit)',
        "port < 15001 || port > 15999 || String(port) !== match[1]",
    )
    for snippet in required:
        deny_unless(snippet in source, "polkit rule missing exact guard: " + snippet)
    deny_unless(source.count("return polkit.Result.YES;") == 1, "polkit rule has multiple allow exits")
    deny_unless(source.count("polkit.addRule(") == 1, "polkit rule count is not exact")
    print("polkit byte-pinned structural lint: PASS")


if __name__ == "__main__":
    main()
