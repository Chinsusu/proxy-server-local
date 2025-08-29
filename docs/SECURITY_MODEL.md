
# Security Model and Threats

Threats considered:
- WAN leak when proxy dies -> mitigated by default drop and per-client DROP on DOWN.
- Credential theft -> store secrets server-side; never echo; use Argon2id for user passwords.
- API abuse -> JWT with short TTL; RBAC; rate limiting on auth endpoints.
- MITM -> enforce HTTPS; HSTS; secure cookies; CSRF tokens for form posts in UI.
- Lateral movement -> UI/API run as non-root; Agent is the only component with CAP_NET_ADMIN.

Hardening:
- Optional strict OUTPUT policy: allow only uid 'pgw' to contact upstream proxy IPs and OS package mirrors.
- System users: pgw:pgw; binaries with AmbientCapabilities only for agent.
- Audit log for create/update/delete operations.
- Secret rotation: JWT secret and DB creds loaded from env; rolling restart propagates.
