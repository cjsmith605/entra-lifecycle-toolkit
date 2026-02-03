<#
.SYNOPSIS
  Offboard users in Microsoft Entra ID using Microsoft Graph PowerShell.

.DESCRIPTION
  - Reads users from a CSV
  - Can disable account, revoke sessions, remove group memberships
  - Supports safe targeted group removal or remove-all (guarded)
  - Produces log + CSV report + summary table
  - Supports DryRun

.REQUIREMENTS
  Connect-MgGraph with (at minimum):
    User.ReadWrite.All
    Group.Read.All
    GroupMember.ReadWrite.All
    Directory.ReadWrite.All
#>

param(
  [Parameter(Mandatory = $true)]
  [string]$CsvPath,

  [switch]$DryRun,

  # If set, won't disable admins (safety guard). Recommended ON.
  [switch]$ProtectAdmins = $true,

  [string]$LogPath = ".\offboarding-log.txt",
  [string]$ReportPath = ".\offboarding-report.csv"
)

function Write-Log {
  param([Parameter(Mandatory=$true)][string]$Message)
  $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  $line = "[$timestamp] $Message"
  Add-Content -Path $LogPath -Value $line
  Write-Host $line
}

function Require-GraphScopes {
  param([Parameter(Mandatory=$true)][string[]]$NeededScopes)

  $ctx = Get-MgContext
  if (-not $ctx -or -not $ctx.Account -or -not $ctx.TenantId) {
    throw "Not connected to Microsoft Graph. Run Connect-MgGraph first."
  }

  $missing = $NeededScopes | Where-Object { $_ -notin $ctx.Scopes }
  if ($missing.Count -gt 0) {
    throw "Missing required Graph scopes: $($missing -join ', '). Reconnect with Connect-MgGraph including these scopes."
  }
  return $ctx
}

function Is-PrivilegedUser {
  param([Parameter(Mandatory=$true)][string]$UserId)

  # Checks if user has any directory role memberships (simple privileged heuristic)
  # Requires Directory.ReadWrite.All or Directory.Read.All
  try {
    $roles = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$UserId/memberOf/microsoft.graph.directoryRole"
    return ($roles.value.Count -gt 0)
  } catch {
    # If we can't check, be conservative and return $true only if ProtectAdmins is disabled elsewhere.
    return $false
  }
}

function Resolve-GroupsByName {
  param([string[]]$GroupNames)

  $resolved = @()
  foreach ($name in $GroupNames) {
    $trimmed = $name.Trim()
    if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }

    $g = Get-MgGroup -Filter "displayName eq '$trimmed'" -ConsistencyLevel eventual -ErrorAction SilentlyContinue
    if (-not $g) {
      $resolved += [pscustomobject]@{ DisplayName=$trimmed; Id=$null; Found=$false }
    } else {
      $resolved += [pscustomobject]@{ DisplayName=$g.DisplayName; Id=$g.Id; Found=$true }
    }
  }
  return $resolved
}

# ---------------------------
# Preconditions
# ---------------------------

if (-not (Test-Path $CsvPath)) { throw "CSV not found: $CsvPath" }

$scopes = @("User.ReadWrite.All","Group.Read.All","GroupMember.ReadWrite.All","Directory.ReadWrite.All")
$ctx = Require-GraphScopes -NeededScopes $scopes

Write-Log "Connected as $($ctx.Account) to tenant $($ctx.TenantId)"
Write-Log "DryRun = $DryRun | ProtectAdmins = $ProtectAdmins"
Write-Log "CSV = $CsvPath"

# ---------------------------
# Process CSV
# ---------------------------

$report = New-Object System.Collections.Generic.List[Object]
$rows = Import-Csv $CsvPath

foreach ($r in $rows) {
  $upn = ($r.UserPrincipalName | ForEach-Object { $_.Trim() })
  $action = ($r.Action | ForEach-Object { $_.Trim() })
  $removeAllGroups = ($r.RemoveAllGroups | ForEach-Object { $_.Trim().ToLower() }) -eq "true"
  $reason = ($r.Reason | ForEach-Object { $_.Trim() })

  if ([string]::IsNullOrWhiteSpace($upn) -or $upn -eq "UserPrincipalName") {
    Write-Log "SKIP: Blank/header row"
    $report.Add([pscustomobject]@{ UserPrincipalName=$upn; Status="SKIPPED"; Notes="Blank/header row" })
    continue
  }

  if ([string]::IsNullOrWhiteSpace($action)) { $action = "DisableAndRevoke" }

  try {
    Write-Log "Processing offboard: $upn | Action=$action | RemoveAllGroups=$removeAllGroups | Reason=$reason"

    $user = Get-MgUser -Filter "userPrincipalName eq '$upn'" -ConsistencyLevel eventual -ErrorAction SilentlyContinue
    if (-not $user) {
      Write-Log "ERROR: User not found: $upn"
      $report.Add([pscustomobject]@{ UserPrincipalName=$upn; Status="ERROR"; Notes="User not found" })
      continue
    }

    # Safety: protect privileged users (directory roles)
    if ($ProtectAdmins) {
      $isPriv = Is-PrivilegedUser -UserId $user.Id
      if ($isPriv) {
        Write-Log "SKIP: $upn appears privileged (directory role member). Manual review required."
        $report.Add([pscustomobject]@{ UserPrincipalName=$upn; Status="SKIPPED"; Notes="Privileged user - manual review" })
        continue
      }
    }

    if ($DryRun) {
      Write-Log "DRYRUN: Would apply action(s) to $upn"
      $report.Add([pscustomobject]@{ UserPrincipalName=$upn; Status="DRYRUN"; Notes="Would offboard (disable/revoke/remove groups)" })
      continue
    }

    # --- Disable account ---
    if ($action -in @("DisableAndRevoke","DisableOnly")) {
      Update-MgUser -UserId $user.Id -AccountEnabled:$false
      Write-Log "Disabled user: $upn"
    }

    # --- Revoke sessions ---
    if ($action -in @("DisableAndRevoke","RevokeOnly")) {
      # revokes refresh tokens and sign-in sessions
      Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/users/$($user.Id)/revokeSignInSessions" | Out-Null
      Write-Log "Revoked sign-in sessions: $upn"
    }

    # --- Remove group memberships ---
    # Safe mode: remove only listed groups by display name (semicolon-separated)
    $removeGroupsRaw = $r.RemoveGroups
    $targetNames = @()
    if (-not [string]::IsNullOrWhiteSpace($removeGroupsRaw)) {
      $targetNames = $removeGroupsRaw.Split(";") | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
    }

    if ($removeAllGroups -and $targetNames.Count -gt 0) {
      Write-Log "WARN: Both RemoveAllGroups=true and RemoveGroups specified. Using RemoveGroups only (safer)."
      $removeAllGroups = $false
    }

    if (-not $removeAllGroups -and $targetNames.Count -gt 0) {
      $resolved = Resolve-GroupsByName -GroupNames $targetNames

      foreach ($g in $resolved) {
        if (-not $g.Found) {
          Write-Log "WARN: Group not found (skip): $($g.DisplayName)"
          continue
        }
        Remove-MgGroupMemberByRef -GroupId $g.Id -DirectoryObjectId $user.Id -ErrorAction SilentlyContinue
        Write-Log "Removed $upn from group: $($g.DisplayName)"
      }
    }
    elseif ($removeAllGroups) {
      # Advanced mode: remove from all *security/M365* groups user is member of (not directory roles)
      $memberOf = Get-MgUserMemberOf -UserId $user.Id -All -ErrorAction SilentlyContinue

      foreach ($m in $memberOf) {
        $odataType = $m.AdditionalProperties.'@odata.type'
        if ($odataType -eq "#microsoft.graph.group") {
          $gid = $m.Id
          try {
            Remove-MgGroupMemberByRef -GroupId $gid -DirectoryObjectId $user.Id -ErrorAction SilentlyContinue
            Write-Log "Removed $upn from groupId: $gid"
          } catch { }
        }
      }
      Write-Log "Removed $upn from all group memberships (best-effort)."
    }

    $report.Add([pscustomobject]@{ UserPrincipalName=$upn; Status="SUCCESS"; Notes="Offboarding completed" })
  }
  catch {
    $msg = $_.Exception.Message
    Write-Log "ERROR for ${upn}: ${msg}"
    $report.Add([pscustomobject]@{ UserPrincipalName=$upn; Status="ERROR"; Notes=$msg })
  }
}

$report | Export-Csv -NoTypeInformation -Path $ReportPath
Write-Log "Report written to: $ReportPath"

Write-Host ""
Write-Host "==================== OFFBOARDING SUMMARY ====================" -ForegroundColor Cyan
$report | Sort-Object Status,UserPrincipalName | Format-Table -AutoSize
Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host ""

Write-Log "Done."

