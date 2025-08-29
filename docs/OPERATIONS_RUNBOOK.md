
# Operations Runbook

## Routine
- Check Dashboard daily for DOWN proxies.
- Rotate JWT secret quarterly.
- Backup DB nightly.

## Adding a new proxy
- Configuration -> Proxies -> Add -> Wait for health OK.
- Create mapping(s); verify client can browse and Exit IP matches telemetry.

## Incident: Proxy DOWN
- Confirm on Dashboard.
- Ensure client is in Blocked list.
- Swap mapping to a hot-standby proxy if business requires; Save (health-gated).
- Root cause upstream.

## Backups
- Postgres: pg_dump to S3/NAS daily; retain 7 days.
- SQLite (lab): stop services and copy DB WAL files.

## Upgrades
- Canary one node; agent is backward compatible with API 1.x.
- After upgrade: run `pgw-agent --reconcile`.
