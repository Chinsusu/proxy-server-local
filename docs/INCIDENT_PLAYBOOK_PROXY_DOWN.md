
# Incident Playbook — Proxy DOWN

1) Verify on Dashboard -> Proxy shows DOWN (red).
2) Confirm client is blocked (cannot browse). If not, run agent reconcile and check nft rules.
3) If business requires connectivity:
   - Map client to standby proxy (health-gated).
4) Document incident: root cause at provider, duration, affected clients.
5) Close with postmortem actions (add alert, provider SLA notes).
