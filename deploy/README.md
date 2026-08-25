# PGW production deployment boundary

The committed files in this directory are the only supported source for PGW
systemd units. The installer copies them byte-for-byte and verifies the result;
it does not generate alternate inline units.

## Identities and paths

| Service | Identity | Writable state | Credentials |
|---|---|---|---|
| API | `pgw-api:pgw-control` | DB files, `/run/pgw/control` | JWT, admin PHC, AES key, Agent token, UI proxy token |
| Agent | `pgw-agent`, supplementary `pgw-control,pgw-fwd` | rules, rollback and Forwarder runtime | Agent token |
| Forwarder | `pgw-fwd` | its systemd private runtime only | per-instance proxy pair |
| UI | `pgw-ui` | none | TLS certificate/key and UI proxy token |
| Health | `pgw-health` | none | none |

Only the Agent has `CAP_NET_ADMIN`. Forwarder lifecycle requests pass through
polkit and are accepted only for `pgw-agent`, verbs `start`, `stop`, or
`restart`, and units `pgw-fwd@15001.service` through
`pgw-fwd@15999.service`.

## Boot fail-close sequence

```text
nftables.service loads /etc/nftables.conf
  -> exact include /etc/nftables.d/pgw-base.nft
  -> ExecStartPost pgw-verify-base runs Agent verify-boot-base JSON semantics
  -> systemd-sysctl.service enables IPv4 forwarding
  -> API
  -> Agent
```

The boot configuration never contains `pgw_dynamic`. The verifier checks exact
table/chain/hook/priority/policy/rule ordering/counters and rejects additional
base objects or weakening/dynamic tables. A missing base table or failed semantic
verification fails `nftables.service`; `systemd-sysctl`, API, and Agent therefore do not start. The distro nftables loader is boot
infrastructure; Agent remains the only long-running PGW data-plane writer.
The live verifier reads the complete ruleset too: only the exact base plus an
optional semantically valid `pgw_dynamic` is accepted. Unrelated families,
tables, flowtables, hooks, legacy aliases, and unpaired redirect/allow rules are
release blockers.

## Install, migration, and rollback

Repository scripts are non-root development/rehearsal helpers only. Run the
root-owned static `/usr/local/sbin/pgw-release-launcher --dry-run` first. A legacy `pgw` service identity or
`/etc/sudoers.d/pgw` blocks installation. After reviewing the backup and
migration conditions, explicitly use `--migrate-legacy`. Every real install
creates a mode-0700 snapshot below `/var/backups/pgw/install.*` containing file
existence, contents, nft base state and service enablement/activity state.
Failure triggers automatic restoration.

Updates consume only the root-owned release selected by the independently pinned
trust manifest. They never consume a checkout, compiler, Git state, or caller
environment. Roll back explicitly:

```bash
sudo /usr/local/sbin/pgw-release-launcher --rollback /var/backups/pgw/install.XXXXXXXX
```

UI assets are installed read-only at `/usr/local/share/pgw/web` only after the
committed `deploy/ui-assets.sha256` manifest validates. The installer verifies
the installed manifest and performs local TLS GET smoke checks for the index,
application JavaScript, login JavaScript, and stylesheets.

## UI proxy token rotation

`/etc/pgw/credentials-current/ui_proxy_token` resolves to an immutable root-owned
credential generation, is mode `0600`, at least 32 random bytes,
and is exposed through systemd credentials only to API and UI. The current
application accepts one token, so rotation is a transactional maintenance
operation rather than a dual-token overlap:

1. Retain the current token only inside the mode-0700 installer snapshot as the
   rollback `previous`; never copy it to environment files or logs.
2. Stop UI, atomically publish the new token, restart API, then restart UI.
3. Run login/proxy smoke checks. On any failure, restore the exact previous
   token and both units from the snapshot before starting UI again.
4. After the observation window, expire the rollback snapshot according to the
   approved retention policy.

This current/previous policy prevents a request signed with the new token from
reaching an API still holding the previous token. Concurrent acceptance of two
tokens is not claimed.

Before rollout, Linux release evidence must include `bash -n`,
`bash deploy/tests/hardening_test.sh`, `systemd-analyze verify`,
`systemd-analyze security`, polkit positive/negative checks, a reboot proving
base-before-forwarding, and a canary failure proving no direct WAN packet.
