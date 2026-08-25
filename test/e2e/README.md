# Data-plane network namespace lab

`netns_legacy_web_only.sh` retains its Wave 0 filename for CI compatibility but
is now the Wave 1 enforcement lab. It creates three isolated Linux network
namespaces, renders the independent base and dynamic rules via `pkg/nft`,
validates them with `nft -c`, and checks:

- mapped TCP/80 is redirected to the local forwarder port;
- mapped TCP/8443 is not sent directly to WAN;
- mapped UDP and forwarded IPv6 are denied;
- unmapped clients are denied by the static base kill-switch;
- named drop/accept/redirect counters observe their corresponding probes;
- an invalid dynamic reconcile cannot remove or bypass the base table.

Run on an isolated Linux host with root privileges:

```bash
sudo bash ./test/e2e/netns_legacy_web_only.sh
```

Or invoke the opt-in Go test wrapper used by a future privileged runner:

```bash
sudo env PGW_RUN_NETNS_E2E=1 go test -count=1 -v ./test/e2e
```

The Wave 1 lab always enforces the base kill-switch. An explicit disable is
rejected instead of silently falling back to legacy characterization:

```bash
sudo env PGW_E2E_REQUIRE_BASE_KILL_SWITCH=1 bash ./test/e2e/netns_legacy_web_only.sh
```

The script requires `go`, `ip`, `nft`, `python3`, `curl`, and `tcpdump`. It
does not contact production services or deploy PGW binaries.

## Preserving evidence

Set `PGW_E2E_ARTIFACT_DIR` to retain the rendered product ruleset, applied
ruleset JSON/text, counter JSON, resource manifest, probe log, and test-server
logs after cleanup:

```bash
sudo env PGW_E2E_ARTIFACT_DIR=/tmp/pgw-wave0-evidence \
  bash ./test/e2e/netns_legacy_web_only.sh
```

`PGW_EVIDENCE_DIR` is supported as a compatibility fallback when
`PGW_E2E_ARTIFACT_DIR` is unset. If neither variable is set, the harness writes
artifacts beneath its temporary directory and deliberately deletes them during
cleanup; only console output remains.

Wave 1 writes the real `nft -j list counters` result as valid JSON and declares
`counter_mode=required` in `product-manifest.txt`. The combined rendered
ruleset, installer-owned base ruleset, mapping-owned dynamic ruleset, applied
rules and invalid-candidate fail-close evidence are retained separately.
