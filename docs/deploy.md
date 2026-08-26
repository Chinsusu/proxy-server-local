# Deploy PGW

PGW uses a self-managed deployment model. The gateway owner can build, verify,
approve, and deploy their own release. No GitHub Organization, reviewer team,
external attestation service, or second operator is required.

## Release checklist

1. Start from an exact Git commit and record it.
2. Run format, unit, integration, and release-candidate verification checks.
3. Record candidate and manifest SHA-256 values.
4. Back up the gateway database, configuration, last-known-good rules, and
   current release.
5. Transfer only the verified candidate to a root-owned directory under
   `/opt/pgw/inbox/` on the gateway and verify its SHA-256 again.
6. Run the candidate launcher in adoption dry-run mode before the real apply:

   ```bash
   sudo /opt/pgw/inbox/<release>/assembly/pgw-release-launcher \
     --adopt /opt/pgw/inbox/<release>/assembly --dry-run
   ```

7. Adopt and apply the candidate. Existing v1 installations require the
   explicit migration flag:

   ```bash
   sudo /opt/pgw/inbox/<release>/assembly/pgw-release-launcher \
     --adopt /opt/pgw/inbox/<release>/assembly --migrate-legacy \
     --lan ens19 --wan eth0
   ```

   Adoption stages the verified payload in `/opt/pgw/releases/`, installs the
   root-owned launcher, and then re-enters through
   `/usr/local/sbin/pgw-release-launcher`. It does not run a checkout as root.

8. Later dry-runs use the installed launcher:

   ```bash
   sudo /usr/local/sbin/pgw-release-launcher --dry-run
   ```

9. Canary one LAN client; verify exit IP, DNS, HTTP/HTTPS behavior, blocked
   UDP/IPv6, and no direct-WAN traffic.
10. Keep the backup for the soak period and roll back immediately on a failed
   health check or policy violation.

## Safety boundaries

The API, UI and Forwarder never receive permission to install services or edit
nftables. The release launcher remains the only root entrypoint. This is a
technical boundary that protects a running gateway; it is unrelated to GitHub
reviews.

Do not run a checkout, `git pull`, or a hand-copied binary as root. Use the
release candidate selected in the checklist so the deployed bytes are known and
recoverable.

## Candidate ownership

The owner selects the originating, pinned release candidate using its recorded
SHA-256 and manifest digest.
The launcher revalidates every allowlisted payload file before installation.
GitHub CI artifacts are convenient release transport, not a second approval
authority.
