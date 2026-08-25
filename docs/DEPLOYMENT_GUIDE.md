# Deployment guide

The former v1 manual-unit guide is retired. It used a shared service user and
manual firewall operations that are incompatible with PGW v2 isolation and
fail-close startup.

Use the transactional procedure in `docs/deploy.md`. Do not copy binaries,
replace SQLite/UDS files, generate units or alter service state outside the
reviewed installer.
