
# Project Kickoff Checklist — Proxy Gateway Manager (v1.1)
Generated: 2025-08-29 03:50

## A. People & Access
- [ ] Assign roles (PM, Tech Lead, Backend, Agent, UI, QA, DevOps)
- [ ] GitHub org/repo created; branch protections on `main`
- [ ] Secrets management decided (env files path, who can access)
- [ ] CI runners available

## B. Environment
- [ ] Target host Ubuntu 22.04 with eth0 (WAN) and ens19 (LAN 192.168.2.1/24)
- [ ] nftables installed and enabled
- [ ] Postgres or SQLite decision finalized
- [ ] NATS (or Redis streams) choice finalized

## C. Docs & Scope
- [ ] Read **SCOPE_LOCK_v1.1.md** and **Definition of Done** in **ROADMAP.md**
- [ ] Review **API_SPEC.yaml** and **DB_SCHEMA.sql**
- [ ] Review **TEST_PLAN.md** acceptance criteria

## D. Non-code Assets
- [ ] Create issue templates and PR template in GitHub
- [ ] Create environment template file from **ENV_TEMPLATE.env**
- [ ] Copy **deploy/systemd/** units and **deploy/docker-compose.yml** if applicable

## E. Dry-run
- [ ] Bring up Postgres + NATS (docker compose) — see **DEPLOYMENT_GUIDE.md**
- [ ] Import **DB_SCHEMA.sql**
- [ ] Smoke test: nftables table `inet pgw` can be created (no conflicts)
- [ ] Prepare client VM in 192.168.2.0/24 for later e2e test
