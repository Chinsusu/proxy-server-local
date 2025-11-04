# Patch: Always-On Traffic (Static Mapping, Health as Telemetry Only)

**Goal:** Keep NAT redirect and mapping static regardless of health-check status. Traffic flows until upstream actually fails.

---

## Summary of Changes

### Files Modified
1. **cmd/api/config.go** (NEW)
   - Added `PGW_ENFORCE_HEALTH` env var (default: `false`)
   - Controls whether health status affects routing

2. **cmd/api/main.go**
   - Updated `/v1/mappings/active` handler to respect `EnforceHealth` flag

3. **cmd/fwd/main.go**
   - Added `dialTimeout()` function
   - Configurable via `PGW_FWD_DIAL_TIMEOUT` (default: 5s)
   - Updated dial calls to use `dialTimeout()` instead of hardcoded 10s

### Files NOT Modified (by design)
- **cmd/health/main.go** - Already correct; only updates telemetry
- **cmd/agent/main.go** - Reconcile behavior unchanged; receives all active mappings

---

## Detailed Changes

### 1. Config File: `cmd/api/config.go` (NEW)

```go
package main

import (
	"os"
	"strconv"
)

// getEnvBool reads a boolean environment variable with a default value
func getEnvBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

// EnforceHealth determines whether /v1/mappings/active filters by proxy health.
// Default false: traffic stays always-on, only health telemetry updates.
var EnforceHealth = getEnvBool("PGW_ENFORCE_HEALTH", false)
```

**How it works:**
- Read `PGW_ENFORCE_HEALTH` env var at startup
- Default to `false` (always-on mode)
- If `true`, reverts to old behavior (filter by health)

---

### 2. API Handler: `/v1/mappings/active` in `cmd/api/main.go`

**Before:**
```go
views := st.ListMappings()
for i := range views {
    if strings.ToUpper(views[i].State) == "FAILED" {
        continue  // Always skip FAILED mappings
    }
    // ... rest of logic
}
```

**After:**
```go
views := st.ListMappings()
for i := range views {
    // When PGW_ENFORCE_HEALTH=false (default): include all mappings
    // When PGW_ENFORCE_HEALTH=true: skip FAILED mappings
    if EnforceHealth && strings.ToUpper(views[i].State) == "FAILED" {
        continue
    }
    // ... rest of logic
}
```

**Flow:**
1. By default (`PGW_ENFORCE_HEALTH=false`):
   - `/v1/mappings/active` returns **ALL mappings**, including FAILED
   - Agent reconciles nftables with all mappings
   - NAT redirect `client_ip:80/443 → :15001` **always applied**

2. If `PGW_ENFORCE_HEALTH=true`:
   - Original behavior: skip FAILED mappings
   - Useful for strict health-based blocking

---

### 3. Forwarder: `dialTimeout()` in `cmd/fwd/main.go`

**Added function:**
```go
func dialTimeout() time.Duration {
    if v := os.Getenv("PGW_FWD_DIAL_TIMEOUT"); v != "" {
        if d, err := time.ParseDuration(v); err == nil {
            return d
        }
    }
    return 5 * time.Second
}
```

**Updated dial calls:**
```go
// Before:
pc, err := net.DialTimeout("tcp", proxyAddr, 10*time.Second)

// After:
pc, err := net.DialTimeout("tcp", proxyAddr, dialTimeout())
```

**Effects:**
- Configurable timeout via `PGW_FWD_DIAL_TIMEOUT` env var
- Default 5 seconds (faster than original 10s)
- Prevents hangs on unreachable upstream
- Graceful failure: returns error, request fails (502/timeout), but mapping stays active

---

## Environment Variables

### API
- **`PGW_ENFORCE_HEALTH`** (default: `false`)
  - `false`: Traffic always on (new default)
  - `true`: Old behavior (filter by health)

### Forwarder
- **`PGW_FWD_DIAL_TIMEOUT`** (default: `5s`)
  - How long to wait for TCP connect to upstream proxy
  - Format: `1s`, `500ms`, `10s`, etc.
  - Example: `PGW_FWD_DIAL_TIMEOUT=3s`

---

## Behavior After Patch

### Traffic Scenarios

**Scenario 1: Proxy is healthy**
```
Client → NAT :80 → :15001 → Forwarder → CONNECT upstream → Success ✓
```

**Scenario 2: Proxy is DOWN but mapping enabled**
```
Client → NAT :80 → :15001 → Forwarder → CONNECT upstream → Timeout → Error 502 ✓
(Mapping stays active; individual request fails, not mapping)
```

**Scenario 3: Health-check reports DOWN, then UP**
```
- Health check fails: status → "down", but traffic STAYS OPEN
- Health check succeeds: status → "up"
- No nftables rule changes, no "blink"
```

### Key Properties

| Aspect | Behavior |
|--------|----------|
| NAT Redirect | ✓ Always active (when mapping enabled) |
| Forwarder Port | ✓ Always listening on :15001 |
| Health Loop | ✓ Updates telemetry every 30s |
| Proxy Down | ✓ Request fails, mapping doesn't toggle |
| Routing Stability | ✓ No flapping based on health checks |
| Default Safety | ✓ Traffic always on (conservative) |

---

## Testing

### Build
```bash
cd /opt/proxy-server-local
make clean
make build
```

### Run API
```bash
PGW_ENFORCE_HEALTH=false pgw-api
```

### Test Mapping Always Returns
```bash
curl -s http://127.0.0.1:8080/v1/mappings/active | jq .
# Should return ALL mappings, including FAILED state ones
```

### Test Forwarder Timeout
```bash
# Point to unreachable upstream
PGW_FWD_DIAL_TIMEOUT=2s pgw-fwd :15001
# Should timeout after 2s, not hang
```

---

## Rollback

If you need to revert:
```bash
git checkout cmd/api/main.go cmd/fwd/main.go
rm cmd/api/config.go
```

Or to revert just the behavior (keep code):
```bash
PGW_ENFORCE_HEALTH=true pgw-api  # Use old filtering logic
```

---

## Commit Message

```
feat(policy): Always-on traffic — stop enforcing health on routing

- API: /v1/mappings/active no longer filters by proxy health by default
- Config: PGW_ENFORCE_HEALTH env var (default=false) for backward compatibility
- Health: no changes; still only updates status/latency/exit_ip
- Forwarder: add PGW_FWD_DIAL_TIMEOUT (default 5s) for graceful upstream failures
- Result: NAT redirect & mappings stay active; individual requests fail if upstream down
```

---

## FAQ

**Q: Will traffic get cut if a proxy fails?**
A: No. Individual requests will fail (502/timeout), but the mapping/route stays active. Health status doesn't affect routing.

**Q: What if I want the old strict behavior?**
A: Set `PGW_ENFORCE_HEALTH=true` to filter mappings by health status again.

**Q: Why 5s timeout instead of 10s?**
A: Faster detection of dead upstreams, but still allows legitimate slow connections (e.g., high latency links). Adjustable via `PGW_FWD_DIAL_TIMEOUT`.

**Q: Do I need to restart services?**
A: Yes, after deploying new binaries. Env vars are read at startup.

---

## Implementation Notes

- `EnforceHealth` is a package-level variable; initialized at startup from env
- Health-check loop (`runHealthTick`) already didn't toggle enabled state; no changes needed there
- Agent reconciles ALL active mappings → nftables rules always present (unless explicitly disabled)
- Forwarder dial timeout is per-connection; doesn't affect overall server operation
