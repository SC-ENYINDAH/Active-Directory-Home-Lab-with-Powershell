#Requires -Version 5.1
<#
.SYNOPSIS
    AD Security Console - interactive terminal dashboard for Active Directory
    security monitoring and auditing.
.DESCRIPTION
    Menu-driven, read-only console front end over Modules\AdSecurityAudit.psm1.
    Run individual checks or a full audit, view color-coded findings, and
    export an HTML report.
.NOTES
    Requires the RSAT 'ActiveDirectory' PowerShell module and read access to
    the target domain. This tool only reads AD data - it makes no changes.
.EXAMPLE
    .\AdSecurityConsole.ps1
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module (Join-Path $scriptRoot 'Modules\AdSecurityAudit.psm1') -Force

$banner = @'
+====================================================================+
|                                                                    |
|   ###  ####       #### #####  #### #   # ####  ##### ##### #   #   |
|  #   # #   #     #     #     #     #   # #   #   #     #    # #    |
|  ##### #   #      ###  ###   #     #   # ####    #     #     #     |
|  #   # #   #         # #     #     #   # #  #    #     #     #     |
|  #   # ####      ####  #####  ####  ###  #   # #####   #     #     |
|              ####  ###  #   #  ####  ###  #     #####              |
|             #     #   # ##  # #     #   # #     #                  |
|             #     #   # # # #  ###  #   # #     ###                |
|             #     #   # #  ##     # #   # #     #                  |
|              ####  ###  #   # ####   ###  ##### #####              |
|                                                                    |
|            Active Directory Security & Audit Dashboard             |
|                                                                    |
+====================================================================+
'@

function Show-Banner {
    Clear-Host
    Write-Host $banner -ForegroundColor Cyan

    $domain = 'UNKNOWN (ActiveDirectory module unavailable)'
    try {
        $domain = (Get-ADDomain -ErrorAction Stop).DNSRoot
    } catch { }

    Write-Host ("  Domain : {0}" -f $domain) -ForegroundColor White
    Write-Host ("  Host   : {0}" -f $env:COMPUTERNAME) -ForegroundColor White
    Write-Host ("  User   : {0}" -f $env:USERNAME) -ForegroundColor White
    Write-Host ("  Time   : {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) -ForegroundColor White
    Write-Host ''
}

function Show-Menu {
    Write-Host '  ====================== MAIN MENU ======================' -ForegroundColor DarkCyan
    Write-Host '   1) Privileged group membership audit'
    Write-Host '   2) Stale user accounts'
    Write-Host '   3) Stale computer accounts'
    Write-Host '   4) Accounts with non-expiring passwords'
    Write-Host '   5) Locked out accounts'
    Write-Host '   6) Kerberoasting exposure (SPN accounts)'
    Write-Host '   7) AS-REP roasting exposure'
    Write-Host '   8) Unconstrained delegation'
    Write-Host '   9) AdminSDHolder / adminCount anomalies'
    Write-Host '  10) Password policy summary'
    Write-Host '  11) Domain trusts'
    Write-Host '  12) Recently created accounts (last 7 days)'
    Write-Host '  13) Accounts expiring soon'
    Write-Host '  --------------------------------------------------------'
    Write-Host '  A) Run FULL audit (all checks)'
    Write-Host '  R) Export last results to HTML report'
    Write-Host '  Q) Quit'
    Write-Host '  ========================================================' -ForegroundColor DarkCyan
    Write-Host ''
}

function Invoke-MenuChoice {
    param([string]$Choice)

    switch ($Choice.ToUpper()) {
        '1'  { return Get-AdPrivilegedGroupAudit }
        '2'  { return Get-AdStaleUserAccounts }
        '3'  { return Get-AdStaleComputerAccounts }
        '4'  { return Get-AdNonExpiringPasswordAccounts }
        '5'  { return Get-AdLockedOutAccounts }
        '6'  { return Get-AdKerberoastableAccounts }
        '7'  { return Get-AdAsRepRoastableAccounts }
        '8'  { return Get-AdUnconstrainedDelegation }
        '9'  { return Get-AdAdminCountAnomalies }
        '10' { return Get-AdPasswordPolicySummary }
        '11' { return Get-AdDomainTrusts }
        '12' { return Get-AdRecentlyCreatedAccounts }
        '13' { return Get-AdExpiringAccounts }
        'A'  { return Invoke-AdFullSecurityAudit }
        default { return $null }
    }
}

# --- Startup checks ---------------------------------------------------------

if (-not (Test-AdModuleAvailable)) {
    Clear-Host
    Write-Host $banner -ForegroundColor Cyan
    Write-Host ''
    Write-Host '  [!] The ActiveDirectory PowerShell module is not available.' -ForegroundColor Red
    Write-Host '      Install RSAT (run as Administrator):' -ForegroundColor Yellow
    Write-Host '      Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0' -ForegroundColor Yellow
    Write-Host '      ...or run this console from a domain controller / management host with RSAT installed.' -ForegroundColor Yellow
    Write-Host ''
    Read-Host '  Press Enter to exit'
    exit 1
}

$script:LastResults = @()

# --- Main loop ----------------------------------------------------------------

do {
    Show-Banner
    Show-Menu
    $choice = Read-Host '  Select an option'

    if ($choice.ToUpper() -eq 'Q') { break }

    if ($choice.ToUpper() -eq 'R') {
        if ($script:LastResults.Count -eq 0) {
            Write-Host '  No results to export yet - run a check first.' -ForegroundColor Yellow
        } else {
            $path = Export-AdSecurityReport -Findings $script:LastResults
            Write-Host "  Report exported to: $path" -ForegroundColor Green
        }
        Read-Host '  Press Enter to continue'
        continue
    }

    $results = Invoke-MenuChoice -Choice $choice
    if ($null -eq $results) {
        Write-Host '  Invalid selection.' -ForegroundColor Red
        Start-Sleep -Seconds 1
        continue
    }

    $script:LastResults = @($results)
    Write-Host ''
    $script:LastResults | Show-FindingsTable
    Show-AuditSummary -Findings $script:LastResults

    Write-Host '  [R] export this view to HTML   [Enter] return to menu' -ForegroundColor DarkGray
    $post = Read-Host '  '
    if ($post.ToUpper() -eq 'R') {
        $path = Export-AdSecurityReport -Findings $script:LastResults
        Write-Host "  Report exported to: $path" -ForegroundColor Green
        Read-Host '  Press Enter to continue'
    }

} while ($true)

Write-Host ''
Write-Host '  AD Security Console closed.' -ForegroundColor Cyan
