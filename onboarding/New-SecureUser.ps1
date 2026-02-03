<#
.SYNOPSIS
  Secure user onboarding for Microsoft Entra ID using Microsoft Graph PowerShell.

.DESCRIPTION
  - Creates users from a CSV
  - Adds users to specified groups
  - Optionally creates Temporary Access Pass (TAP) for first sign-in
  - Writes logs and a summary report (NO passwords or TAP codes written to disk)
  - Supports DryRun

.REQUIREMENTS
  Connect-MgGraph with these scopes (at minimum):
    User.ReadWrite.All
    Group.ReadWrite.All
    GroupMember.ReadWrite.All
    Directory.ReadWrite.All
    UserAuthenticationMethod.ReadWrite.All  (only needed if using TAP)
#>

param(
  [Parameter(Mandatory = $true)]
  [string]$CsvPath,

  [Parameter(Mandatory = $true)]
  [string[]]$TargetGroups,  # e.g. "LIC-BASELINE-USERS","GRP-SECURITY-NEW-HIRES"

  [switch]$DryRun,

  # TAP controls
  [switch]$NoTap,
  [int]$TapLifetimeMinutes = 60,
  [switch]$TapUsableOnce,

  # Output files
  [string]$LogPath = ".\onboarding-log.txt",
  [string]$ReportPath = ".\onboarding-report.csv"
)

# ---------------------------
# Helpers
# ---------------------------

function Write-Log {
  param([Parameter(Mandatory=$true)][string]$Message)
  $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  $line = "[$timestamp] $Message"
  Add-Content -Path $LogPath -Value $line
  Write-Host $line
}

function Require-GraphScopes {
  param(
    [Parameter(Mandatory=$true)][string[]]$NeededScopes
  )

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

function New-TapForUser {
  param(
    [Parameter(Mandatory=$true)][string]$UserId,
    [int]$LifetimeMinutes = 60,
    [bool]$IsUsableOnce = $false
  )

  $uri = "https://graph.microsoft.com/v1.0/users/$UserId/authentication/temporaryAccessPassMethods"

  $body = @{
    startDateTime      = (Get-Date).ToUniversalTime().ToString("o")
    lifetimeInMinutes  = $LifetimeMinutes
    isUsableOnce       = $IsUsableOnce
  } | ConvertTo-Json

  return Invoke-MgGraphRequest -Method POST -Uri $uri -Body $body -ContentType "application/json"
}

# ---------------------------
# Preconditions
# ---------------------------

if (-not (Test-Path $CsvPath)) {
  throw "CSV not found: $CsvPath"
}

# Base scopes always needed for user + group operations
$baseScopes = @(
  "User.ReadWrite.All",
  "Group.ReadWrite.All",
  "GroupMember.ReadWrite.All",
  "Directory.ReadWrite.All"
)

# Only require TAP scope if we're not skipping TAP
$scopesToRequire = $baseScopes
if (-not $NoTap) {
  $scopesToRequire += "UserAuthenticationMethod.ReadWrite.All"
}

$ctx = Require-GraphScopes -NeededScopes $scopesToRequire

Write-Log "Connected as $($ctx.Account) to tenant $($ctx.TenantId)"
Write-Log "DryRun = $DryRun"
Write-Log "CSV = $CsvPath"
Write-Log "Groups = $($TargetGroups -join ', ')"
Write-Log "NoTap = $NoTap | TapLifetimeMinutes = $TapLifetimeMinutes | TapUsableOnce = $($TapUsableOnce.IsPresent)"

# Resolve group IDs upfront (fail early if names are wrong)
$resolvedGroups = @()
foreach ($gName in $TargetGroups) {
  $g = Get-MgGroup -Filter "displayName eq '$gName'" -ConsistencyLevel eventual -ErrorAction Stop
  if (-not $g) { throw "Group not found: $gName" }
  $resolvedGroups += [pscustomobject]@{ DisplayName = $g.DisplayName; Id = $g.Id }
}
Write-Log "Resolved groups: $($resolvedGroups.DisplayName -join ', ')"

# ---------------------------
# Process CSV
# ---------------------------

$report = New-Object System.Collections.Generic.List[Object]
$rows = Import-Csv $CsvPath

foreach ($r in $rows) {
  $upn = ($r.UserPrincipalName | ForEach-Object { $_.Trim() })

  # --- Guardrails ---
  if ([string]::IsNullOrWhiteSpace($upn)) {
    Write-Log "SKIP: Blank UserPrincipalName row"
    $report.Add([pscustomobject]@{ UserPrincipalName=""; Status="SKIPPED"; Notes="Blank row" })
    continue
  }

  # Skip accidental header rows inside CSV (common copy/paste issue)
  if ($upn -eq "UserPrincipalName" -or $r.UsageLocation -eq "UsageLocation") {
    Write-Log "SKIP: Detected header row inside CSV"
    $report.Add([pscustomobject]@{ UserPrincipalName=$upn; Status="SKIPPED"; Notes="Header row detected" })
    continue
  }

  if ($upn -notmatch ".+@.+") {
    Write-Log "SKIP: Invalid UPN format: ${upn}"
    $report.Add([pscustomobject]@{ UserPrincipalName=$upn; Status="SKIPPED"; Notes="Invalid UPN format" })
    continue
  }

  $usage = ($r.UsageLocation.Trim()).ToUpper()
  if ($usage -notmatch "^[A-Z]{2}$") {
    Write-Log "SKIP: Invalid UsageLocation for ${upn}: '${usage}' (expected 2-letter code like US)"
    $report.Add([pscustomobject]@{ UserPrincipalName=$upn; Status="SKIPPED"; Notes="Invalid UsageLocation" })
    continue
  }

  try {
    Write-Log "Processing user: $upn"

    # Check if user already exists
    $existing = Get-MgUser -Filter "userPrincipalName eq '$upn'" -ConsistencyLevel eventual -ErrorAction SilentlyContinue
    if ($existing) {
      Write-Log "SKIP: $upn already exists (Id=$($existing.Id))"
      $report.Add([pscustomobject]@{ UserPrincipalName=$upn; Status="SKIPPED"; Notes="User already exists" })
      continue
    }

    if ($DryRun) {
      Write-Log "DRYRUN: Would create user and add to groups."
      $report.Add([pscustomobject]@{ UserPrincipalName=$upn; Status="DRYRUN"; Notes="Would create + group (+TAP if enabled)" })
      continue
    }

    # Generate strong temporary password (NOT logged)
    $tempPassword = -join ((33..126) | Get-Random -Count 20 | ForEach-Object { [char]$_ })

    $userBody = @{
      AccountEnabled     = $true
      DisplayName        = $r.DisplayName
      MailNickname       = ($upn.Split("@")[0])
      UserPrincipalName  = $upn
      GivenName          = $r.GivenName
      Surname            = $r.Surname
      Department         = $r.Department
      JobTitle           = $r.JobTitle
      UsageLocation      = $usage
      PasswordProfile    = @{
        Password = $tempPassword
        ForceChangePasswordNextSignIn = $true
      }
    }

    $newUser = New-MgUser -BodyParameter $userBody

    if (-not $newUser -or [string]::IsNullOrWhiteSpace($newUser.Id)) {
      throw "User creation failed for ${upn}; aborting group assignment and TAP."
    }

    Write-Log "Created user: $upn (Id=$($newUser.Id))"

    # Add to target groups
    foreach ($grp in $resolvedGroups) {
      New-MgGroupMember -GroupId $grp.Id -DirectoryObjectId $newUser.Id
      Write-Log "Added $upn to group: $($grp.DisplayName)"
    }

    # Create TAP (console only)
    if (-not $NoTap) {
      try {
        $tap = New-TapForUser -UserId $newUser.Id -LifetimeMinutes $TapLifetimeMinutes -IsUsableOnce:$TapUsableOnce.IsPresent

        Write-Host ""
        Write-Host "============================================================" -ForegroundColor DarkGray
        Write-Host "TEMPORARY ACCESS PASS (show once) for: $upn" -ForegroundColor Yellow
        Write-Host "TAP: $($tap.temporaryAccessPass)" -ForegroundColor Yellow
        Write-Host "Lifetime: $TapLifetimeMinutes minutes | One-time use: $($TapUsableOnce.IsPresent)" -ForegroundColor DarkGray
        Write-Host "============================================================" -ForegroundColor DarkGray
        Write-Host ""
      }
      catch {
        Write-Log "WARN: TAP creation failed for ${upn}. User created and grouped. Error: $($_.Exception.Message)"
      }
    }

    $report.Add([pscustomobject]@{ UserPrincipalName=$upn; Status="SUCCESS"; Notes="Created + grouped" })
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
Write-Host "==================== ONBOARDING SUMMARY ====================" -ForegroundColor Cyan
$report | Sort-Object Status,UserPrincipalName | Format-Table -AutoSize
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Log "Done."

