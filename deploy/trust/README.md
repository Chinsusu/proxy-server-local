# Self-managed release verification

This directory contains compatibility material from the former external
attestation design. PGW no longer requires an independent signing service,
organization reviews, GitHub OIDC, or a custom trust root for an owner-managed
deployment.

The supported self-managed release path is:

1. Select an exact source commit and build one candidate.
2. Verify the candidate SHA-256 and release manifest locally.
3. Back up the gateway.
4. Transfer only the verified candidate to the gateway.
5. Run the root-owned launcher in dry-run mode, then deploy.
6. Canary one client and retain the backup until the soak period succeeds.

Do not execute an arbitrary checkout as root and do not skip the backup or
canary. Those are operational safeguards, not organization workflow.

Use the candidate's `pgw-release-launcher --adopt <assembly> --dry-run` command
to verify a root-owned staged candidate, then rerun it without `--dry-run` to
stage and apply. Do not attempt to satisfy the retired format with fabricated
keys, bundles, or policy files.
