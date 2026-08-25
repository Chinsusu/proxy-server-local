# Historical Forwarder binding incident

This is a historical v1 incident marker, not an operational runbook. The old
manual scripts and direct instance-management procedure are retired.

PGW v2 writes a validated concrete-LAN `listen_address` in Agent-owned runtime,
passes credentials through systemd, waits for `Type=notify`, and publishes the
redirect only after readiness. Changes and rollback use `docs/deploy.md`.
