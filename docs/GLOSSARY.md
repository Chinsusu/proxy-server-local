
# Glossary

- Agent: service that programs nftables and enforces policy.
- Mapping: 1:1 assignment between client IP and upstream proxy.
- Forwarder: local listener that dials the selected upstream proxy.
- Health telemetry: status/latency/exit_ip of a proxy.
- No-leak design: enforcement to ensure LAN traffic never goes to WAN directly.
- SSE: Server-Sent Events used by UI for live updates.
