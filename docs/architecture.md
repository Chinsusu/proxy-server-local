# PGW v2 architecture

## Trust boundaries

- `pgw-ui`: HTTPS presentation and proxy to public API routes; no Agent access.
- `pgw-api`: domain transactions, SQLite, encryption and audit; no nftables or
  systemd authority.
- `pgw-agent`: only application service with `CAP_NET_ADMIN`; sole dynamic
  nftables writer and Forwarder lifecycle manager.
- `pgw-fwd@<port>`: unprivileged TCP proxy adapter with per-instance systemd
  credentials.
- `pgw-health`: read-only health observer.

API and Agent use `/run/pgw/control/api-agent.sock`, protected by filesystem
group and a scoped service token. Internal Agent endpoints are never exposed on
TCP. UI talks only to API with a separate proxy identity token.

## State model

SQLite stores proxies, encrypted secrets, clients, policies, mappings, nodes,
reconcile state, idempotency keys and append-only audit events. Every active
mapping contains desired state, generation, proxy/credential revisions and a
local redirect port. JSON is import/export only.

Agent fetches an immutable snapshot, validates it, compares its canonical hash,
prepares required runtime, checks the nft candidate, applies one dynamic-table
transaction, reads back the semantic hash, atomically saves LKG, then ACKs. One
worker coalesces pending generations with `pending=max`; reconciles never run in
parallel.

## Fail-close data plane

`inet pgw_base` is static boot infrastructure. It blocks all LAN→WAN forwarding
unless traffic is consumed by a verified local redirect; UDP and IPv6 remain
blocked by current policy. Agent must not flush or replace the base table.
Management accepts are explicitly IPv4 and limited to the configured LAN and
loopback. The IPv6 management drop precedes every accept, and non-LAN IPv4 is
explicitly denied.

The dynamic table contains only current source mappings and TCP redirects.
Forwarder readiness is systemd `Type=notify`; a TCP probe against the transparent
listener is forbidden. Credential rotation or spec revision causes a protected
runtime replacement before redirect publication.

## Runtime recovery

LKG lives in `/var/lib/pgw/rules`. Before destructive runtime replacement Agent
writes and fsyncs a checksum-bound, non-secret transition journal. Same-process
failure restores the old runtime and LKG before ACK. Startup recovery either
restores a valid protected `/run` restore point or quarantines affected redirects
and rebuilds desired state; it never claims rollback without verification.

## Privilege and lifecycle

Static users isolate API, Agent, Forwarder, UI and health. Agent has only
`CAP_NET_ADMIN`; narrow polkit permits start/stop/restart only for validated
Forwarder instance units. Secrets arrive through systemd credentials.

The reviewed installer is the only supported publisher. It serializes all
lifecycle operations, quiesces writers/Forwarders before DB/UDS changes, and
restores files, rules, forwarding and exact service state on failure. It forces
`net.ipv4.ip_forward=0` before every mutation and recovery step; saved forwarding
is restored only after exact nft semantic readback, service readiness, binary
identity, and snapshot metadata verification succeed.
