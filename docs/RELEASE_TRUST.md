# PGW self-managed release model

PGW is maintained and deployed by its owner. One maintainer may make a change,
build the release, run validation, approve it, and deploy it to their own
gateway.

## What is required

For every release, keep these technical controls:

- build from an exact Git commit and record that commit;
- produce a release candidate and record its SHA-256 and manifest SHA-256;
- run the project test suite and candidate verification before transfer;
- back up the gateway before changing services or firewall state;
- use the supported root-owned launcher rather than executing a checkout as
  root;
- dry-run first, canary one LAN client, then keep a rollback point through the
  soak period; and
- stop and roll back if any direct-WAN packet, plaintext secret, SQLite
  integrity failure, or failed health check is detected.

## What is optional

The following may be used by a team, but never block an owner-managed release:

- a GitHub Organization or team membership;
- pull-request approval, CODEOWNERS, or protected environments;
- an external attestor repository, GitHub OIDC, Sigstore, or a separate
  evidence repository; and
- a second operator or a change-management ceremony.

Checksums, manifests, local test results, gateway logs, packet capture, and a
backup are sufficient evidence for this project.

## Transitional note

The self-managed launcher adopts a root-owned candidate directory with:

```bash
sudo /opt/pgw/inbox/<release>/assembly/pgw-release-launcher \
  --adopt /opt/pgw/inbox/<release>/assembly --dry-run
sudo /opt/pgw/inbox/<release>/assembly/pgw-release-launcher \
  --adopt /opt/pgw/inbox/<release>/assembly --migrate-legacy \
  --lan ens19 --wan eth0
```

The dry-run verifies the candidate without writing the gateway. Apply stages
the payload under `/opt/pgw/releases/`, atomically installs the fixed launcher
and trust manifest, then invokes the installed launcher. A direct checkout
install remains unsupported.
