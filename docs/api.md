# PGW v2 API contract

Public `/v2` resources cover proxies, clients, egress policies, mappings, Agent
state and append-only audit. Mutations require `Idempotency-Key`; versioned
changes use `If-Match`. Lists use cursor pagination (default 50, maximum 200).

Errors use `{error:{code,message,details},request_id}`. Public proxy responses
contain username and `password_configured`, never plaintext password.

`/v1` remains a migration compatibility layer for one cycle. Reads are redacted
and all writes execute through the v2 application/domain transaction.

## Internal Agent API

All `/internal/agent/v1/*` routes are available only on
`/run/pgw/control/api-agent.sock` and require the scoped Agent service token:

- immutable desired snapshot by generation;
- active mapping credential with proxy/credential revision;
- reconcile ACK with generation and desired/applied hashes;
- reconcile state.

The internal API is never exposed through UI or TCP. Agent health and metrics
remain cheap loopback-only endpoints; the scoped trigger is authenticated POST
and coalesced before any API fetch.
