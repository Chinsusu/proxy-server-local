# PGW v2 UI

UI serves HTTPS from the verified read-only asset tree and proxies only public
API routes to `PGW_UI_API`. A scoped UI proxy token authenticates that hop.

UI has no Agent route, Agent token, nftables capability or systemd authority.
Desired/applied/data-plane state shown in the UI comes from the public API.

Smoke test the deterministic login route and static assets as documented in
`docs/deploy.md`.
