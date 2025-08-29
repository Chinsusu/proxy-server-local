
# Requirement Traceability — v1.1

| Req ID | Requirement | Source | Design/Spec | Test(s) |
|---|---|---|---|---|
| R-001 | Each client egress only via mapped proxy | User brief | TECHNICAL_DESIGN_v1.1 §1/4/5 | ENF-001/002, FAIL-001 |
| R-002 | Health check every 30s; record exit IP & latency | User brief | TECHNICAL_DESIGN_v1.1 §3 | HLTH-001 |
| R-003 | Auto-apply rules only after health OK | User brief | API_SPEC `/mappings` + Agent | UI-001, HLTH-001 |
| R-004 | Block and no WAN leak when proxy DOWN | User brief | No-Leak Design §4 + nft | FAIL-001, ENF-002, No-leak capture |
| R-005 | UI tabs: Dashboard/Proxy Mappings/Configuration/Authentication | User brief | UI_SPEC | UI-001 |
| R-006 | Auth with JWT + roles | User brief | SECURITY_MODEL, API_SPEC | AUTH-001 |
| R-007 | Deployment guides & artifacts | User brief | DEPLOYMENT_GUIDE | OPS-001 |
