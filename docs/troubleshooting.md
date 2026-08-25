# PGW v2 troubleshooting

Start with `docs/QUICK_OPS.md`. Separate control-plane state (API/Agent
generation, UDS, audit) from data-plane evidence (base/dynamic rule hashes,
Forwarder readiness, proxy/destination logs and packet capture).

Never bypass Agent by changing dynamic nftables or Forwarder units manually.
Keep `pgw_base` intact and use the transactional rollback when binary, DB,
ruleset or service identity is inconsistent.
