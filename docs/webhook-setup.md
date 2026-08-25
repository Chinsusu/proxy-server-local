# Webhook deployment is unsupported

PGW v2 does not ship, enable, or support `pgw-webhook.service`. Incoming
webhooks must never pull source, build binaries, overwrite production files,
or restart PGW automatically.

Production updates use an already reviewed local checkout and the guarded
installer:

```bash
sudo /usr/local/sbin/pgw-release-launcher --dry-run
sudo /usr/local/sbin/pgw-release-launcher
```

The root compatibility wrapper additionally requires
The retired checkout wrapper cannot select a commit or release. Production
release selection comes only from the root-owned pinned trust manifest.

Every update creates an exact rollback snapshot under `/var/backups/pgw`.
Rollback is explicit and restores binaries, UI assets, database/LKG, units,
configuration, file metadata, and prior service state.
