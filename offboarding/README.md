# Offboarding (Offboard-User.ps1)

Offboards Entra users from a CSV by disabling accounts, revoking sessions, and removing group memberships.

## Files
- Offboard-User.ps1
- offboard_users.sample.csv

## Prereqs
- PowerShell 7+
- Microsoft Graph PowerShell SDK
- Tenant permissions to disable users, revoke sessions, and manage group membership

## Connect to Microsoft Graph (example scopes)
  Connect-MgGraph -Scopes "User.ReadWrite.All","Group.Read.All","GroupMember.ReadWrite.All","Directory.ReadWrite.All"
  Select-MgProfile -Name "v1.0"

## Dry run (recommended first)
  ./Offboard-User.ps1 -CsvPath ./offboard_users.sample.csv -DryRun

## Live run
  ./Offboard-User.ps1 -CsvPath ./offboard_users.sample.csv

## Safety notes
- Includes a ProtectAdmins guard to reduce risk of disabling privileged accounts without review.
- Supports removing only specified groups (recommended) or remove-all mode (advanced).
