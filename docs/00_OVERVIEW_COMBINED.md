# PGW v2 overview

This file supersedes the former combined v1 design notes. Those notes described
file/in-memory stores, UI-to-Agent HTTP calls and API-managed Forwarders; none of
those historical mechanisms are valid production procedures.

## Packet path

1. Client traffic enters LAN `ens19`.
2. Static `inet pgw_base`, loaded before IPv4 forwarding, blocks every direct
   LAN→WAN path.
3. Agent validates one immutable desired snapshot and prepares the mapped
   per-port Forwarder.
4. Only after systemd reports the Forwarder `active/running` from `Type=notify`
   does Agent atomically publish the dynamic redirect.
5. Forwarder connects only to the explicitly configured upstream proxy. There
   is no direct fallback.

Suspend/delete reverses the order: Agent removes the redirect, drains up to 30
seconds, stops the Forwarder and removes credential runtime material.

## Control plane

```text
Browser --HTTPS--> UI --scoped proxy token--> API --SQLite--> pgw.db
                                             ^
                                             |
                         UDS + Agent token ---+--- Agent
                                                   |
                                      nftables + systemd/polkit
                                                   |
                                             pgw-fwd@PORT
```

- SQLite `/var/lib/pgw/pgw.db` is authoritative.
- API encrypts proxy secrets with AES-256-GCM and never returns plaintext.
- Agent communicates with API only through protected UDS for snapshot,
  credentials and ACK.
- UI proxies public API routes only; it cannot reach or trigger Agent directly.
- Agent alone owns dynamic nftables and Forwarder lifecycle.

## Failure and recovery

Static base policy remains fail-close if any application service exits. Agent
uses generation/hash verification, exact nft readback, LKG and a durable
non-secret runtime-transition journal. A failed apply restores verified LKG and
the matching old Forwarder; after reboot without a valid secret restore point it
quarantines the redirect rather than risk old-rule/new-proxy misrouting.

## Production lifecycle

The transactional installer snapshots files, SQLite, LKG/runtime, full nftables
ruleset, `ip_forward`, service state and every Forwarder instance after all
writers have been quiesced. Rollback restores and verifies the exact snapshot,
including process binary identity. See `docs/deploy.md`.

Historical v1 documents or scripts, if retained for incident archaeology, are
not executable runbooks and must never override this v2 contract.
