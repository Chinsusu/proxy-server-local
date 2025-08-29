
# Proxy Gateway Manager — Skeleton v1.1 (Go)

This is a minimal, compilable skeleton aligned with the docs pack.
Binaries:
- cmd/api     -> control-plane REST API (stub)
- cmd/ui      -> tiny UI placeholder
- cmd/agent   -> agent with /agent/reconcile stub
- cmd/health  -> periodic health loop (logs only)
- cmd/fwd     -> placeholder TCP listener

## Build
```
make build
```

## Run (in separate shells)
```
make run-api
make run-ui
make run-agent
make run-health
make run-fwd
```

## Notes
- Store/events are in-memory/no-op to keep skeleton portable.
- Implement nftables, NATS, Postgres according to Docs Pack v1.1.
