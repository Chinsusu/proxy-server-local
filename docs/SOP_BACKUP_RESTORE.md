
# SOP — Backup & Restore

## Backup (Postgres)
- Nightly `pg_dump -Fc pgw > /backups/pgw_$(date +%F).dump`
- Retain 7 days; upload to S3/NAS

## Restore
- `pg_restore -d pgw pgw_<date>.dump`
- Restart services in order: DB -> NATS -> API -> Agent -> Health -> UI

## SQLite (lab)
- Stop services; copy `pgw.db*` files atomically
