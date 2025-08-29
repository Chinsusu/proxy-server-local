
# UI/UX Spec

Navigation tabs: Dashboard, Proxy Mappings, Configuration, Authentication.

## Dashboard
- Cards: Total Proxies (OK/DEGRADED/DOWN), Total Clients, Blocked Clients, Recent Events.
- Small table "Unhealthy Proxies" sorted by latency/last_checked.

## Proxy Mappings
Table columns:
- Client IP
- Proxy Server (host:port)
- Username (masked)
- Status (OK/DEGRADED/DOWN with latency ms)
- Exit IP
- Actions (Edit, Delete)

Add Mapping form:
- Client IP (text, /32)
- Select existing Proxy
- Protocol (http/socks5)
- Port (default 1080 for HTTP, 1080 for socks5 unless specified by proxy)
- On Save: backend runs health gate; only apply if status OK/DEGRADED.

## Configuration
- Health interval (default 30s)
- Latency thresholds
- DNS mode (minimal or enhanced)
- Strict host OUTPUT mode (on/off)

## Authentication
- Users list
- Add user (email, role)
- Reset password

Design language: Tailwind, dark theme, compact tables, responsive; uses HTMX for partial updates and SSE for live badges.
