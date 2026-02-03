# Entra Lifecycle Toolkit (Onboarding + Offboarding)

PowerShell + Microsoft Graph automation for Microsoft Entra ID joiner/leaver workflows.

## What this repo does
- Onboarding: Create users from CSV, populate attributes, add to groups, optionally issue Temporary Access Pass (TAP).
- Offboarding: Disable users, revoke sessions, remove group memberships, export audit-friendly reports.

## Security / design highlights
- Dry-run mode to validate changes before execution
- Idempotent behavior (safe to re-run; skips existing users)
- Auditability via logs + CSV reports
- Secure handling of TAP (printed to console only, never written to disk)

## Repo layout
- onboarding/  -> onboarding automation + sample CSV
- offboarding/ -> offboarding automation + sample CSV
- docs/        -> sanitized example outputs/screenshots

## Quick start
See:
- onboarding/README.md
- offboarding/README.md
