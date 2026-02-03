# Onboarding (New-SecureUser.ps1)

Creates Microsoft Entra ID users from a CSV and adds them to one or more groups.
Optionally issues a Temporary Access Pass (TAP) for initial sign-in.

## Files
- New-SecureUser.ps1
- new_users.sample.csv

## Prereqs
- PowerShell 7+
- Microsoft Graph PowerShell SDK
- Tenant permissions to create users and manage groups

Install Graph module (one time):
  Install-Module Microsoft.Graph -Scope CurrentUser

## Connect to Microsoft Graph (example scopes)
  Connect-MgGraph -Scopes "User.ReadWrite.All","Group.ReadWrite.All","GroupMember.ReadWrite.All","Directory.ReadWrite.All","UserAuthenticationMethod.ReadWrite.All"
  Select-MgProfile -Name "v1.0"

## Dry run (recommended first)
  ./New-SecureUser.ps1 -CsvPath ./new_users.sample.csv -TargetGroups "LIC-BASELINE-USERS","GRP-SECURITY-NEW-HIRES" -DryRun

## Live run with TAP
  ./New-SecureUser.ps1 -CsvPath ./new_users.sample.csv -TargetGroups "LIC-BASELINE-USERS","GRP-SECURITY-NEW-HIRES" -TapUsableOnce -TapLifetimeMinutes 60

## Notes
- TAP codes are shown in the console only and are never written to log/report files.
- The script skips existing users to remain safe to re-run.
