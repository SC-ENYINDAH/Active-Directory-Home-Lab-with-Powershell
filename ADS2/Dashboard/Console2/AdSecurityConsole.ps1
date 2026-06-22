[CmdletBinding()]
param(
    [string]$Server,
    [pscredential]$Credential
)

$ErrorActionPreference = 'Stop'
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module (Join-Path $PSScriptRoot '.\AdSecurityAudit.psm1') -Force

$banner = @'
+===================================================================================================================+
|                                                                                                                   |
|   ###  ####       #### #####  #### #   # ####  ##### ##### #   #    ####   ###   #   #   ####   ###  #     #####  |
|  #   # #   #     #     #     #     #   # #   #   #     #    # #    #      #   #  ##  #  #      #   # #     #      |
|  ##### #   #      ###  ###   #     #   # ####    #     #     #     #      #   #  # # #    ###  #   # #     #####  |
|  #   # #   #         # #     #     #   # #  #    #     #     #     #      #   #  #   #       # #   # #     #      |
|  #   # ####      ####  #####  ####  ###  #   # #####   #     #      ####   ###   #   #  ####    ###  ##### #####  |
|                                                                                                                   |
|                             Active Directory Security and Audit Dashboard                                         |
|                                                                                                                   |
|                                                                                                                   |
+===================================================================================================================+
'@

function Show-Banner {
    Clear-Host
    Write-Host $banner -ForegroundColor Cyan -BackgroundColor Black

    $conn = Get-AdConnection
    $target = if ($conn.ContainsKey('Server')) { $conn['Server'] } else { 'auto (DNS-located DC)' }
    $asUser = if ($conn.ContainsKey('Credential')) { $conn['Credential'].UserName } else { "$env:USERDOMAIN\$env:USERNAME (current session)" }

    Write-Host ("  Management Host : {0}" -f $env:COMPUTERNAME) -ForegroundColor White
    Write-Host ("  Querying        : {0}" -f $target) -ForegroundColor White
    Write-Host ("  As              : {0}" -f $asUser) -ForegroundColor White
    Write-Host ("  Time            : {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) -ForegroundColor White
    Write-Host ''
}

function Show-ConnectionSetup { 
    while ($true) {
        Clear-Host
        Write-Host $banner -ForegroundColor Cyan -BackgroundColor Black
        Write-Host ''
        Write-Host '  --- AD CONNECTION SETUP ---' -ForegroundColor DarkCyan
        Write-Host ''

        $useAltCred = Read-Host '  Domain or DC to query (FQDN, e.g. contoso.com or dc01.contoso.com)
  [Use alternate credentials for a not domain-joined host = (y/N)]'

        if ($useAltCred.ToUpper() -eq 'Y') {
            $credential = Get-Credential -Message 'Enter credentials for the domain (e.g. user@contoso.com)'
            $computerName =  Read-Host 'Enter network address for the domain (e.g. 127.0.0.1)'

        }

        $serverInput = $useAltCred

        if ($serverInput -and $credential) {
            Set-AdConnection -Server $serverInput -DomainAddress $computerName -Credential $credential
        } elseif ($serverInput) {
            Set-AdConnection -Server $serverInput
        } elseif ($credential) {
            Set-AdConnection -Credential $credential
        } elseif ($computerName) {
            Set-AdConnection -DomainAddress $computerName
        }else {
            Set-AdConnection
        }

        Write-Host ''
        Write-Host '  Testing connectivity...' -ForegroundColor Yellow
        $test = Test-AdConnectivity

        if ($test.Success) {
            Write-Host "  [OK] $($test.Message)" -ForegroundColor Green
            #Write-Host "       Domain      : $($test.DomainName)" -ForegroundColor Green
            #Write-Host "       PDC Emulator: $($test.PDCEmulator)" -ForegroundColor Green
            Write-Host ''
            Read-Host '  Press Enter to continue to the dashboard'
            return $true
        }

        Write-Host "  [FAILED] $($test.Message)" -ForegroundColor Red
        Write-Host ''
        Write-Host '  Common causes on a management host:' -ForegroundColor Yellow
        Write-Host '    - DNS cannot resolve the target domain from this host' -ForegroundColor Yellow
        Write-Host '    - TCP/9389 (Active Directory Web Services) is blocked between this host and the DC' -ForegroundColor Yellow
        Write-Host '    - This host is not domain-joined and no/incorrect alternate credential was supplied' -ForegroundColor Yellow
        Write-Host '    - Clock skew between this host and the domain (Kerberos requires close time sync)' -ForegroundColor Yellow
        Write-Host ''
        $retry = Read-Host '  Try again? (Y/n)'
        if ($retry.ToUpper() -eq 'N') { return $false }
    }
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
    Write-Host '  C) Reconfigure AD connection'
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
        'C'  { return Set-AdConnection }
        default { return $null }
    }
}

# --- Startup checks ---------------------------------------------------------
<#
if (-not (Test-AdModuleAvailable)) {
    Clear-Host
    Write-Host $banner -ForegroundColor Cyan -BackgroundColor Black
    Write-Host ''
    Write-Host '  [!] The ActiveDirectory PowerShell module is not available on this management host.' -ForegroundColor Red
    Write-Host '      Install RSAT (run as Administrator):' -ForegroundColor Yellow
    Write-Host '      Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0' -ForegroundColor Yellow
    $install = Read-Host '  Press Y to install RSAT, or any other key to exit'
    if ($install.ToUpper() -eq 'Y') {
        Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
        Write-Host '  RSAT installation initiated. Please re-run the console after installation completes.' -ForegroundColor Green
        Get-WindowsCapability -Name "Rsat.ActiveDirectory.DS-LDS.Tools*" -Online
        Write-Host 'Verifying RSAT installation...' -ForegroundColor Yellow
        Start-Sleep -Seconds 5
        if (Test-AdModuleAvailable) {
            Write-Host '  RSAT installation completed successfully.' -ForegroundColor Green
        }
    }
    Write-Host ''
    exit 1
}
#>
# Allow non-interactive pre-configuration via -Server / -Credential parameters;
# still verify connectivity before proceeding either way.
if ($Server -or $Credential) {
    if ($Server -and $Credential) { Set-AdConnection -Server $Server -Credential $Credential }
    elseif ($Server)               { Set-AdConnection -Server $Server }
    else                            { Set-AdConnection -Credential $Credential }

    $preTest = Test-AdConnectivity
    if (-not $preTest.Success) {
        Write-Host "  [FAILED] $($preTest.Message)" -ForegroundColor Red
        if (-not (Show-ConnectionSetup)) { exit 1 }
    }
} else {
    if (-not (Show-ConnectionSetup)) { exit 1 }
}

$script:LastResults = @()

# --- Main loop ----------------------------------------------------------------

do {
    Show-Banner
    Show-Menu
    $choice = Read-Host '  Select an option'

    if ($choice.ToUpper() -eq 'Q') { break }

    if ($choice.ToUpper() -eq 'C') {
        if (-not (Show-ConnectionSetup)) { break }
        continue
    }

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
