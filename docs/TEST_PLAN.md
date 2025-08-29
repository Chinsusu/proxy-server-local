
# Test Plan (v1.1)

## 1. Unit tests
- Health checker: simulate HTTP and SOCKS5 success/timeout/auth failure.
- Agent diff engine: given desired mappings -> emits expected nft changes.
- JWT middleware and RBAC.

## 2. Integration tests (docker)
- Bring up tinyproxy (http) and dante (socks5).
- Seed one client 192.168.2.3/32.
- Verify:
  - Mapping created -> rules present, tcpdump shows redirect to 127.0.0.1:<port>.
  - Drop upstream proxy -> Agent switches client to DROP within 1s.
  - Ensure no packets leave via eth0 when proxy is down (tcpdump -i eth0 host 192.168.2.3 == 0).

## 3. E2E acceptance
- UI flows: create/edit/delete proxy; add mapping; latency/exit IP visible.
- Latency color badges and SSE updates.
- Block-on-fail acceptance with browser from client VM.

## 4. Regression and Chaos
- Restart NATS -> system still reconciles via DB polling.
- Reboot host -> systemd ensures rules recreated.
- DB readonly -> agent keeps enforcing last good state.


## 5. Acceptance Criteria (v1.1)

1) **No-leak**: With mapped proxy forced DOWN, tcpdump on `eth0` shows **0 packets** from the client IP for 60s window while client generates traffic.
   - Cmd: `sudo tcpdump -i eth0 host <client_ip> -c 1 -w /tmp/wan_leak.pcap` must **not** capture anything.
2) **Block-on-fail latency**: From proxy status flip to `DOWN` to client being actively dropped **<1s** (event path) and **<5s** (poll path).
3) **Health telemetry**: After adding a proxy, `exit_ip` and `latency_ms` are recorded within **≤5s** and displayed in UI.
4) **Mapping apply gate**: Attempt to map client to an unhealthy proxy is **rejected** by API and **no** nftables rule is created.
5) **Persistence after reboot**: Reboot host -> within **≤5s** of services startup, nftables rules for all mappings are present.
6) **Auth**: Viewer cannot mutate resources; Admin can. Passwords stored as Argon2id hashes.
7) **Scale smoke**: Create **256** mappings; UI stays responsive; Agent reconcile completes in **≤10s** and all listeners exist.
8) **DNS minimal mode**: UDP/53 from clients is dropped; `dig` from client times out; browsing via proxy still works.

## 6. Test Matrix

| Area | Test ID | Description | Tooling | Pass/Fail |
|---|---|---|---|---|
| Enforcement | ENF-001 | PREROUTING redirect per client | nft list ruleset |  |
| Enforcement | ENF-002 | FORWARD drop LAN->WAN | tcpdump/nft |  |
| Failover | FAIL-001 | Proxy DOWN -> DROP <1s | curl loop + kill upstream |  |
| Health | HLTH-001 | Latency/exit IP captured | ipify + UI |  |
| UI | UI-001 | Add/Edit/Delete mapping flows | Playwright/cypress |  |
| Auth | AUTH-001 | RBAC admin/viewer | API calls |  |
| Perf | PERF-001 | 256 mappings overhead | wrk/hey + metrics |  |
| Ops | OPS-001 | Reboot re-apply | reboot + verify |  |

## 7. Go/CI Quality Gates

- go test ./... (≥80% coverage on core packages `pkg/nft`, `pkg/check`, `pkg/auth`).
- golangci-lint run (no critical findings).
- `make e2e` runs dockerized integration; report artifacts: ruleset, pcap, logs.
- SAST (gosec) no high issues.
