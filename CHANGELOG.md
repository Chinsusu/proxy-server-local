# Changelog

## [1.2.0] - 2026-02-14

### Fixed
- **Critical: `ListMappings` bug** — PENDING mappings were invisible because `append` was incorrectly nested inside `if m.LastAppliedAt != nil` block in `memoryStore`. New mappings now appear immediately in UI and Agent.

### Security
- **JWT secret validation at startup** — API refuses to start if `PGW_JWT_SECRET` is the insecure default (`dev-change-me`) or shorter than 32 characters. Bypass with `PGW_JWT_STRICT=false` for development.
- **Login rate limiting** — 5 failed login attempts per IP within 15 minutes triggers `429 Too Many Requests`.
- **Request body size limits** — All POST endpoints now enforce 1 MB max body via `http.MaxBytesReader`.

### Added
- **Unit tests** — 25 tests across `pkg/store`, `pkg/auth`, `pkg/config` covering CRUD, cascade deletes, JWT sign/parse, Argon2id hash/verify, and config validation.
- **Forwarder hot-reload** — `pgw-fwd` now polls API every 30s (configurable via `PGW_FWD_POLL_INTERVAL`) and supports `SIGHUP` for immediate upstream re-resolve. No restart needed when proxy changes.
- **Graceful shutdown** — API server handles `SIGTERM`/`SIGINT` with 10s drain timeout.

### Improved
- **Parallel health checks** — `runHealthTick` now uses a worker pool (max 10 concurrent) instead of sequential checks, significantly faster with many proxies.
- **Structured logging** — Added `log/slog` JSON handler alongside legacy loggers for structured, machine-parseable log output. New code can use `logging.L` (slog) or `logging.With()` for context fields. Legacy `logging.Info/Warn/Error` kept for backward compatibility.
- **Startup config validation** — API validates network interfaces (`PGW_WAN_IFACE`, `PGW_LAN_IFACE`), `nft` binary availability, forwarder port range, and data directory at startup, logging warnings for any issues found.

### Fixed (Disk Full Prevention)
- **Batch telemetry writes** — Health check tick now calls `SetProxyTelemetryBatch()` once per tick instead of `SetProxyTelemetry()` per proxy, reducing disk writes from N×`save()` to 1×`save()` per tick cycle.
- **Sampled forwarder logging** — `pgw-fwd` now logs 1 in every 100 successful connections (configurable via `PGW_FWD_LOG_SAMPLE`), reducing log volume by ~99% under heavy traffic. Errors always logged.
- **Journald size limit** — Added `deploy/journald-pgw.conf` drop-in (`SystemMaxUse=500M`, `SystemKeepFree=1G`, rotate weekly) to prevent unbounded journal growth.
