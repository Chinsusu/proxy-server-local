# RACI Matrix (v1.1)

This is a personal, single-maintainer project: one person is Responsible and
Accountable for every workstream (requirements, API/DB design, health
service, Agent/nftables, UI, deployment, testing, security, release). A
role matrix would only restate that on every row, so this file records the
governance model instead of a table.

The separations that actually protect this system are process and
trust-domain separations, not people separations:

- The Agent alone owns dynamic nftables state; the installer alone owns the
  static base table; neither crosses into the other's objects.
- Release trust is anchored outside CI (the external attestor trust domain,
  provisioned by the maintainer but independent of the repo and its
  workflows) - see RELEASE_TRUST.md.
- Machine gates (required status checks, hardening contracts, secret scan,
  rehearsal evidence) gate every change; none of them require a second
  person.
