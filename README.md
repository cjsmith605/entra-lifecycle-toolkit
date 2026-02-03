# Entra Lifecycle Toolkit (Onboarding + Offboarding)

PowerShell + Microsoft Graph automation for Microsoft Entra ID joiner/leaver workflows.

## Intended audience

This project is designed to demonstrate hands-on IAM skills for:
- Identity & Access Management (IAM) Analyst roles
- Junior Identity / Cloud Security Engineer roles
- Security Analyst roles with Entra ID or Azure AD exposure

The workflows align with real-world Joiner–Mover–Leaver (JML) identity lifecycle practices
and Microsoft SC-300 objectives.

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

## Evidence (sanitized)

This repository includes sanitized example outputs demonstrating how the scripts behave
in real Microsoft Entra ID environments.

- Onboarding examples (dry-run and execution):
  - `docs/onboarding-output.example.txt`

- Offboarding examples (dry-run and execution):
  - `docs/offboarding-output.example.txt`

All examples are sanitized:
- No tenant IDs
- No object IDs
- No Temporary Access Pass (TAP) values

