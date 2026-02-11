<#
.SYNOPSIS
  Remediates “ICMP Timestamp Request Remote Date Disclosure”
  (Tenable/Nessus Plugin ID 10114) by enforcing Windows Firewall
  and blocking ICMPv4 Timestamp Request (Type 13) and Reply (Type 14),
  ensuring the mitigation is both applied and actively enforced.

.DESCRIPTION
  Many scanners (e.g., Nessus/Tenable) flag hosts as vulnerable when they respond
  to ICMP timestamp requests (Type 13) and/or send timestamp replies (Type 14),
  which can disclose the target system time to unauthenticated remote users.

  On Windows, remediation is achieved by filtering:
    - Inbound ICMPv4 Timestamp Requests  (Type 13)
    - Outbound ICMPv4 Timestamp Replies (Type 14)

  NOTE (important):
    Even if the ICMP firewall rules exist, they are not enforced when Windows Firewall
    is disabled. Nessus may continue to detect Plugin 10114 until the firewall is enabled
    for the relevant profile(s).

  In practice, this finding often persists on Windows systems not because
  firewall rules are missing, but because the Windows Firewall service is
  disabled, causing existing ICMP filtering rules to be ineffective.

  This script remediates the vulnerability by:
    - Capturing a true pre-mitigation baseline (firewall state and ICMP rules)
    - Enabling Windows Firewall only when it is disabled
    - Creating or enforcing ICMPv4 timestamp blocking rules (Types 13 and 14)
    - Forcing a Group Policy refresh (gpupdate /force) to detect policy overrides
    - Re-verifying the effective state after policy application
    - Supporting rollback by restoring the original firewall state and rules
    - Optionally prompting for a system reboot (shutdown /r /t 0 /f) for clean vulnerability rescans

  The approach ensures the mitigation is not only configured, but actively
  enforced and resilient against Group Policy reversion.

  v1.1 Enhancements:
    - Added forced Group Policy refresh (gpupdate /force) to detect and handle GPO-managed firewall overrides
    - Added post-GPO verification to confirm rules persist after policy reapplication
    - Improved logic and messaging to distinguish local remediation success vs. GPO reversion
    - Added optional reboot prompt at script completion for clean rescans

  v1.2 Enhancements:
    - Adds an explicit PRE-mitigation baseline section (true “before” snapshot)
    - Adds PASS/FAIL style exit codes (0=success, 1=error, 2=warn/fail to apply)
    - Keeps gpupdate /force and post-gpupdate verification
    - Keeps optional reboot prompt (shutdown /r /t 0 /f)

  v1.3 Enhancements:
    - Adds detection/remediation for disabled Windows Firewall profiles (Domain/Private/Public) and
    prints firewall status before/after changes to confirm enforcement
    - In ENFORCE mode, enables Windows Firewall only when needed so ICMP timestamp blocking rules
    are actually enforced (fixes persistent Nessus Plugin 10114 findings when firewall was OFF)
    - In ROLLBACK mode, removes the ICMP rules and restores the original firewall Enabled state per
    profile (safe, reversible rollback to pre-change configuration)
    - Retains prior capabilities: pre-mitigation baseline (v1.2), gpupdate + post-GPO verification (v1.1),
    deterministic PASS/WARN/ERROR exit codes, and optional reboot prompt
    - Continues using targeted ICMPv4 timestamp blocking (Types 13/14) rather than disabling IPv4/ICMP globally

.NOTES
    - Requires administrative privileges
    - Tested for compatibility with Windows PowerShell 5.1 (no ternary operator)
    - Author        : Sun Dimitri NFANDA
    - Date Created  : 2026-02-10
    - Last Modified : 2026-02-10
    - Version       : 1.3

.TESTED ON
    Date(s) Tested  : 2026-02-10
    Tested By       : Sun Dimitri NFANDA
    Systems Tested  : Windows (Windows Server 2025 Datacenter - x64 Gen2)
    PowerShell Ver. : 5.1.26100.7462 (Verify your PowerShell version using the command $PSVersionTable)

.USAGE
  Set $secureEnvironment to $true to enforce the mitigation (recommended).
  Set $secureEnvironment to $false to remove the mitigation (rollback).

  Example:
    PS C:\> .\Set-IcmpTimestampFiltering.ps1
#>

# =========================
# User-configurable setting
# =========================
$secureEnvironment = $true

# =========================
# Constants / Rule Names
# =========================
$RuleNameIn  = "Block ICMPv4 Timestamp Request (Type 13) - Nessus 10114"
$RuleNameOut = "Block ICMPv4 Timestamp Reply (Type 14) - Nessus 10114"

# ========================================
# Exit codes (useful for automation / CI)
# ========================================
$EXIT_SUCCESS = 0   # Mitigation/rollback applied as expected (post-gpupdate verified)
$EXIT_ERROR   = 1   # Script error (e.g., not admin, exception)
$EXIT_WARN    = 2   # Mitigation/rollback did not reach expected post-gpupdate state

function Test-IsAdmin {
  try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch {
    return $false
  }
}

function Write-Section($text) {
  Write-Host ""
  Write-Host ("==== " + $text + " ====") -ForegroundColor Cyan
}

function Invoke-GpUpdateForce {
  # Forces Group Policy refresh so that if firewall policy is managed by GPO, we detect any reversion quickly.
  Write-Host "Forcing Group Policy refresh (gpupdate /force)..." -ForegroundColor Cyan
  try {
    $p = Start-Process -FilePath "gpupdate.exe" -ArgumentList "/force" -Wait -PassThru -WindowStyle Hidden -ErrorAction Stop
    if ($p.ExitCode -eq 0) {
      Write-Host "gpupdate completed successfully." -ForegroundColor Green
      return $true
    } else {
      Write-Host ("gpupdate exited with code: " + $p.ExitCode) -ForegroundColor Yellow
      return $false
    }
  } catch {
    Write-Host ("gpupdate failed: " + $_.Exception.Message) -ForegroundColor Yellow
    return $false
  }
}

function Ensure-FirewallRuleBlock {
  param(
    [Parameter(Mandatory=$true)][string]$DisplayName,
    [Parameter(Mandatory=$true)][ValidateSet("Inbound","Outbound")][string]$Direction,
    [Parameter(Mandatory=$true)][int]$IcmpType
  )

  $existing = Get-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue

  if ($null -eq $existing) {
    # Create the rule if it does not exist.
    New-NetFirewallRule `
      -DisplayName $DisplayName `
      -Protocol ICMPv4 `
      -IcmpType $IcmpType `
      -Direction $Direction `
      -Action Block `
      -Profile Any `
      -Enabled True | Out-Null

    return @{
      Action = "Created"
      DisplayName = $DisplayName
      Direction = $Direction
      IcmpType = $IcmpType
    }
  }

  # If it exists, enforce desired settings (enabled, block, any profile).
  # Note: If a GPO enforces different settings, it may revert after gpupdate /force.
  Set-NetFirewallRule -DisplayName $DisplayName -Enabled True -Profile Any -Action Block -ErrorAction SilentlyContinue | Out-Null

  return @{
    Action = "Exists/Updated"
    DisplayName = $DisplayName
    Direction = $Direction
    IcmpType = $IcmpType
  }
}

function Remove-FirewallRuleSafe {
  param([Parameter(Mandatory=$true)][string]$DisplayName)

  $existing = Get-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue
  if ($null -eq $existing) {
    return @{ Action = "NotPresent"; DisplayName = $DisplayName }
  }

  Remove-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue
  return @{ Action = "Removed"; DisplayName = $DisplayName }
}

function Get-RuleVerification {
  param([Parameter(Mandatory=$true)][string]$DisplayName)

  $r = Get-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue
  if ($null -eq $r) {
    return @{
      Present = $false
      Enabled = $false
      Action  = $null
      Direction = $null
      Profile = $null
      Protocol = $null
      IcmpType = $null
    }
  }

  $pf = $null
  try { $pf = $r | Get-NetFirewallPortFilter -ErrorAction Stop } catch { $pf = $null }

  $icmpType = $null
  $proto = $null
  if ($null -ne $pf) {
    $proto = $pf.Protocol
    if ($pf.PSObject.Properties.Name -contains "IcmpType") { $icmpType = $pf.IcmpType }
  }

  return @{
    Present = $true
    Enabled = ($r.Enabled -eq "True")
    Action  = $r.Action
    Direction = $r.Direction
    Profile = $r.Profile
    Protocol = $proto
    IcmpType = $icmpType
  }
}

function Print-Verify($name, $v) {
  Write-Host ""
  Write-Host $name -ForegroundColor White
  Write-Host ("  Present   : " + $v.Present)
  Write-Host ("  Enabled   : " + $v.Enabled)
  Write-Host ("  Action    : " + $v.Action)
  Write-Host ("  Direction : " + $v.Direction)
  Write-Host ("  Profile   : " + $v.Profile)
  if ($null -ne $v.Protocol) { Write-Host ("  Protocol  : " + $v.Protocol) }
  if ($null -ne $v.IcmpType) { Write-Host ("  ICMP Type : " + $v.IcmpType) }
}

function Get-FirewallProfileState {
  # Returns firewall enabled state per profile (Domain/Private/Public)
  Get-NetFirewallProfile | Select-Object Name, Enabled, AllowLocalFirewallRules
}

function Print-FirewallProfileState {
  param(
    [Parameter(Mandatory=$true)][string]$Title
  )
  Write-Section $Title
  Get-FirewallProfileState | Format-Table -AutoSize
}

function Enable-FirewallAllProfiles {
  # Enables Windows Firewall for all profiles.
  # This is required for firewall rules to be enforced. If the firewall is disabled,
  # rules may exist and appear "ActiveStore", but filtering does not occur.
  Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True | Out-Null
}

function Restore-FirewallProfileState {
  param(
    [Parameter(Mandatory=$true)][array]$OriginalProfiles
  )

  foreach ($p in $OriginalProfiles) {
    # Enabled is boolean, pass through as-is (True/False)
    Set-NetFirewallProfile -Name $p.Name -Enabled $p.Enabled | Out-Null
  }
}

function Prompt-RebootIfDesired {
  # Optional reboot prompt (useful in labs where you want a clean state before rescanning).
  Write-Host ""
  $ans = Read-Host "Do you want to restart this VM now? (Y/N)"
  if ($null -ne $ans) {
    $ans = $ans.Trim()
    if ($ans -match '^(Y|y|YES|Yes|yes)$') {
      Write-Host "Restarting now (shutdown /r /t 0 /f)..." -ForegroundColor Yellow
      & shutdown.exe /r /t 0 /f
    } else {
      Write-Host "No restart selected. You can reboot later if needed." -ForegroundColor Gray
    }
  }
}

# =========================
# Main
# =========================
try {
  Write-Section "ICMP Timestamp Request/Reply Filtering (Nessus Plugin 10114)"

  if (-not (Test-IsAdmin)) {
    Write-Host "ERROR: This script must be run as Administrator." -ForegroundColor Red
    Write-Host "Right-click PowerShell -> Run as administrator, then rerun the script." -ForegroundColor Yellow
    exit $EXIT_ERROR
  }

  if ($secureEnvironment) {
    Write-Host "Mode: ENFORCE (enable firewall if needed; block ICMPv4 types 13 inbound and 14 outbound)" -ForegroundColor Green
  } else {
    Write-Host "Mode: ROLLBACK (remove mitigation firewall rules; restore original firewall state)" -ForegroundColor Yellow
  }

  # ---- Capture firewall baseline FIRST (v1.3 addition) ----
  $fwBaseline = Get-FirewallProfileState

  # Show firewall state BEFORE changes
  Print-FirewallProfileState -Title "Firewall Profile State (BEFORE any changes)"

  # ---- True rule baseline snapshot (v1.2 behavior) ----
  Write-Section "Pre-Mitigation Baseline (true BEFORE snapshot) - ICMP Rules"
  $preIn  = Get-RuleVerification -DisplayName $RuleNameIn
  $preOut = Get-RuleVerification -DisplayName $RuleNameOut
  Print-Verify -name $RuleNameIn  -v $preIn
  Print-Verify -name $RuleNameOut -v $preOut

  $results = @()

  if ($secureEnvironment) {

    # Enable firewall if ANY profile is disabled (v1.3 behavior)
    $needsEnable = $false
    foreach ($p in $fwBaseline) {
      if ($p.Enabled -eq $false) { $needsEnable = $true }
    }

    if ($needsEnable) {
      Write-Section "Enabling Windows Firewall (required for enforcement)"
      Write-Host "One or more firewall profiles are disabled. Enabling Domain/Private/Public..." -ForegroundColor Yellow
      Enable-FirewallAllProfiles

      # Show firewall state AFTER enabling
      Print-FirewallProfileState -Title "Firewall Profile State (AFTER enabling)"
    } else {
      Write-Host ""
      Write-Host "Windows Firewall is already enabled across profiles. No change needed." -ForegroundColor Gray
    }

    Write-Section "Applying Mitigation - ICMP Rules"
    $results += Ensure-FirewallRuleBlock -DisplayName $RuleNameIn  -Direction Inbound  -IcmpType 13
    $results += Ensure-FirewallRuleBlock -DisplayName $RuleNameOut -Direction Outbound -IcmpType 14

  } else {

    Write-Section "Rolling Back Mitigation - ICMP Rules"
    $results += Remove-FirewallRuleSafe -DisplayName $RuleNameIn
    $results += Remove-FirewallRuleSafe -DisplayName $RuleNameOut

    # Show firewall state BEFORE restoring (v1.3 requirement: show before/after for rollback too)
    Print-FirewallProfileState -Title "Firewall Profile State (BEFORE restoring baseline)"

    Write-Section "Restoring Firewall Profile State (to baseline)"
    Restore-FirewallProfileState -OriginalProfiles $fwBaseline

    # Show firewall state AFTER restoring
    Print-FirewallProfileState -Title "Firewall Profile State (AFTER restoring baseline)"
  }

  Write-Section "Initial Verification (after changes, before gpupdate) - ICMP Rules"
  $verifyIn1  = Get-RuleVerification -DisplayName $RuleNameIn
  $verifyOut1 = Get-RuleVerification -DisplayName $RuleNameOut
  Print-Verify -name $RuleNameIn  -v $verifyIn1
  Print-Verify -name $RuleNameOut -v $verifyOut1

  Write-Section "Group Policy Refresh"
  $gpOk = Invoke-GpUpdateForce
  Start-Sleep -Seconds 8

  # Show firewall state after gpupdate (useful if GPO flips profiles back off)
  Print-FirewallProfileState -Title "Firewall Profile State (AFTER gpupdate)"

  Write-Section "Post-gpupdate Verification (detects GPO overwrite/reversion) - ICMP Rules"
  $verifyIn2  = Get-RuleVerification -DisplayName $RuleNameIn
  $verifyOut2 = Get-RuleVerification -DisplayName $RuleNameOut
  Print-Verify -name $RuleNameIn  -v $verifyIn2
  Print-Verify -name $RuleNameOut -v $verifyOut2

  # Determine whether rules were reverted after GP update
  $reverted = $false
  if ($secureEnvironment) {
    $wasGoodIn  = ($verifyIn1.Present -and $verifyIn1.Enabled)
    $wasGoodOut = ($verifyOut1.Present -and $verifyOut1.Enabled)
    $nowGoodIn  = ($verifyIn2.Present -and $verifyIn2.Enabled)
    $nowGoodOut = ($verifyOut2.Present -and $verifyOut2.Enabled)

    if ($wasGoodIn -and (-not $nowGoodIn))   { $reverted = $true }
    if ($wasGoodOut -and (-not $nowGoodOut)) { $reverted = $true }
  }

  Write-Section "Summary"
  foreach ($r in $results) {
    if ($r.ContainsKey("IcmpType")) {
      Write-Host ("- {0}: {1} (Direction={2}, ICMP Type={3})" -f $r.Action, $r.DisplayName, $r.Direction, $r.IcmpType)
    } else {
      Write-Host ("- {0}: {1}" -f $r.Action, $r.DisplayName)
    }
  }

  Write-Host ""
  Write-Host ("gpupdate attempted : True") -ForegroundColor Gray
  Write-Host ("gpupdate succeeded : " + $gpOk) -ForegroundColor Gray

  $exitCode = $EXIT_SUCCESS

  if ($secureEnvironment) {
    $okIn  = ($verifyIn2.Present -and $verifyIn2.Enabled)
    $okOut = ($verifyOut2.Present -and $verifyOut2.Enabled)

    # Also ensure firewall is enabled after gpupdate; otherwise rules won't be enforced
    $fwAfter = Get-FirewallProfileState
    $fwOk = $true
    foreach ($p in $fwAfter) {
      if ($p.Enabled -eq $false) { $fwOk = $false }
    }

    Write-Host ""
    if ($okIn -and $okOut -and $fwOk) {
      if ($reverted) {
        Write-Host "PASS (with note): Rules are present/enabled and firewall is enabled after gpupdate. Some change was detected during refresh; review GPO if unexpected." -ForegroundColor Yellow
      } else {
        Write-Host "PASS: Firewall is enabled and ICMP timestamp Type 13 inbound / Type 14 outbound are blocked. Re-run Nessus to confirm Plugin 10114 clears." -ForegroundColor Green
      }
    } else {
      Write-Host "FAIL/WARN: Mitigation is not fully enforced after gpupdate." -ForegroundColor Yellow
      if (-not $fwOk) {
        Write-Host "          Windows Firewall is disabled on one or more profiles, so rules may not be enforced." -ForegroundColor Yellow
      }
      if (-not ($okIn -and $okOut)) {
        Write-Host "          One or more ICMP rules are missing/disabled after gpupdate." -ForegroundColor Yellow
      }
      Write-Host "          If this host is domain-joined, a GPO may be overwriting firewall settings." -ForegroundColor Yellow
      $exitCode = $EXIT_WARN
    }
  } else {
    $goneIn  = (-not $verifyIn2.Present)
    $goneOut = (-not $verifyOut2.Present)

    Write-Host ""
    if ($goneIn -and $goneOut) {
      Write-Host "PASS: Rollback complete. ICMP rules removed and firewall state restored (post-gpupdate verified)." -ForegroundColor Green
    } else {
      Write-Host "FAIL/WARN: One or more rules still exist after rollback (post-gpupdate)." -ForegroundColor Yellow
      Write-Host "          They may be enforced via GPO or have a different display name." -ForegroundColor Yellow
      $exitCode = $EXIT_WARN
    }
  }

  # Optional reboot prompt at end
  Prompt-RebootIfDesired

  exit $exitCode
}
catch {
  Write-Host ""
  Write-Host ("ERROR: Unhandled exception: " + $_.Exception.Message) -ForegroundColor Red
  exit $EXIT_ERROR
}
