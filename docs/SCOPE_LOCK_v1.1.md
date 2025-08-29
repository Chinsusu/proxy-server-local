
# SCOPE_LOCK_v1.1

This document freezes the scope for the v1.1 delivery.

## IN-SCOPE
- Per-client TCP interception via nftables NAT REDIRECT.
- Health checks every 30s; telemetry (status, latency, exit_ip).
- UI 4 tabs with live updates and CRUD flows.
- Block-on-fail (no WAN fallback) with prove-no-leak tests.
- Minimal DNS handling (drop UDP/53) with optional DoH stub (documented, may be off).
- Deployment artifacts: Docker Compose, systemd units, env template.
- Observability: logs + Prometheus metrics.

## OUT-OF-SCOPE
- UDP proxying, TPROXY mode.
- Bandwidth caps/quotas.
- High Availability/VRRP.
- OAuth2/OIDC login; SSO.
- Multi-tenant isolation beyond roles.
- Per-client TLS interception or domain ACLs.

## CHANGE CONTROL
Any new item not listed in IN-SCOPE requires a new minor (v1.2+) or a signed change request.
