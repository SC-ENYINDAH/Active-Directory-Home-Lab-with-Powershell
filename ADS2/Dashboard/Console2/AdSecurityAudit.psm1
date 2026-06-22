Set-StrictMode -Version Latest

#region Configuration

$script:PrivilegedGroups = @(
    'Domain Admins',
    'Enterprise Admins',
    'Schema Admins',
    'Administrators',
    'Account Operators',
    'Backup Operators',
    'Server Operators',
    'Print Operators',
    'DnsAdmins',
    'Group Policy Creator Owners'
)

$script:StaleAccountDays  = 90   # no logon in this many days = stale
$script:RecentAccountDays = 7    # created in the last N days = "recent"
$script:ExpiringSoonDays  = 14   # account expires within N days


$script:AdSplat = @{}

#endregion

#region Connection
function Set-AdConnection {
    [CmdletBinding()]
    param(
        [string]$Server,
        [pscredential]$Credential,
        [string]$DomainAddress
    )

    $splat = @{}
    if ($Server)     { $splat['Server']     = $Server }
    if ($Credential) { $splat['Credential'] = $Credential }
    if ($DomainAddress) { $splat['DomainAddress'] = $DomainAddress }
    $script:AdSplat += $splat
}

function Get-AdConnection {
    [CmdletBinding()] param()
    
    return $script:AdSplat
}

function Test-AdConnectivity {
       
    [CmdletBinding()] param()

    $result = [PSCustomObject]@{
        Success      = $true
        PortTestDone = $true
        Message      = ''
    }

    if ($script:AdSplat.ContainsKey('Server'), $script:AdSplat.ContainsKey('Credential') -and $script:AdSplat.ContainsKey('DomainAddress')) {
        $targetHost = $script:AdSplat['DomainAddress']
        $UserName = $script:AdSplat['Server']
        $cred = $script:AdSplat['Credential']
        $result.PortTestDone = $true
       
        $portTest = Test-NetConnection -ComputerName $targetHost -WarningAction SilentlyContinue -ErrorAction Stop
    
    }
    
    return $result
}

#endregion

#region Helpers
<#
function Test-AdModuleAvailable {
    <#
    .SYNOPSIS
        Returns $true if the ActiveDirectory module is present and loaded.
    
    [CmdletBinding()]
    param()

    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        return $false
    }
    if (-not (Get-Module -Name ActiveDirectory)) {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
        } catch {
            return $false
        }
    }
    return $true
}
    #2 to check/debug
function New-Finding {
    <#
    .SYNOPSIS
        Builds a standardized finding object used across all audit functions.
   
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][ValidateSet('Critical','High','Medium','Low','Info')][string]$Severity,
        [Parameter(Mandatory)][string]$Object,
        [Parameter(Mandatory)][string]$Detail,
        [string]$Recommendation = ''
    )

    [PSCustomObject]@{
        Timestamp      = Get-Date
        Category       = $Category
        Severity       = $Severity
        Object         = $Object
        Detail         = $Detail
        Recommendation = $Recommendation
    }
}
#>
function Get-SeverityColor {
    param([string]$Severity)
    switch ($Severity) {
        'Critical' { 'Red' }
        'High'     { 'Magenta' }
        'Medium'   { 'Yellow' }
        'Low'      { 'Cyan' }
        default    { 'Green' }
    }
}

#endregion
<#
#region Audit Modules
#3 to check/debug
function Get-AdPrivilegedGroupAudit {
    <#
    .SYNOPSIS
        Recursively enumerates well-known privileged groups and flags
        disabled-but-privileged, never-expiring, old, or dormant accounts.
    
    [CmdletBinding()] param()
    $findings = @()

    foreach ($groupName in $script:PrivilegedGroups) {
        try {
            $group = Get-ADGroup -Identity $groupName @script:AdSplat -ErrorAction Stop
        } catch {
            continue   # group does not exist in this domain (e.g. Schema Admins outside forest root)
        }

        try {
            $members = Get-ADGroupMember -Identity $group -Recursive @script:AdSplat -ErrorAction Stop
        } catch {
            $findings += New-Finding -Category 'Privileged Groups' -Severity 'Low' `
                -Object $groupName -Detail "Could not enumerate members: $($_.Exception.Message)"
            continue
        }

        foreach ($member in $members) {
            if ($member.objectClass -ne 'user') { continue }

            $user = Get-ADUser -Identity $member.distinguishedName `
                -Properties Enabled, PasswordLastSet, LastLogonDate, PasswordNeverExpires `
                @script:AdSplat -ErrorAction SilentlyContinue
            if (-not $user) { continue }

            $passAgeDays = $null
            if ($user.PasswordLastSet) {
                $passAgeDays = (New-TimeSpan -Start $user.PasswordLastSet -End (Get-Date)).Days
            }

            $severity    = 'Info'
            $detailParts = @("member of '$groupName'")

            if (-not $user.Enabled) {
                $severity = 'Medium'
                $detailParts += 'account is DISABLED but retains privileged membership'
            }
            if ($user.PasswordNeverExpires) {
                $severity = 'High'
                $detailParts += 'password set to NEVER EXPIRE'
            }
            if ($null -ne $passAgeDays -and $passAgeDays -gt 365) {
                $severity = 'High'
                $detailParts += "password is $passAgeDays days old"
            }
            if ($user.LastLogonDate -and ((Get-Date) - $user.LastLogonDate).Days -gt $script:StaleAccountDays) {
                $severity = 'Critical'
                $idleDays = ((Get-Date) - $user.LastLogonDate).Days
                $detailParts += "no logon in $idleDays days while holding privileged access"
            }

            $findings += New-Finding -Category 'Privileged Groups' -Severity $severity `
                -Object $user.SamAccountName -Detail ($detailParts -join '; ') `
                -Recommendation 'Review necessity of privileged membership; prefer time-bound / PAW access.'
        }
    }

    return $findings
}
#4 to check/debug
function Get-AdStaleUserAccounts {
    <#
    .SYNOPSIS
        Enabled user accounts with no logon recorded in the configured window.
        Note: LastLogonDate is replicated and can lag up to ~14 days.
   
    [CmdletBinding()] param(
        [int]$Days = $script:StaleAccountDays
    )
    $findings = @()
    $cutoff   = (Get-Date).AddDays(-$Days)

    $users = Get-ADUser -Filter { Enabled -eq $true } -Properties LastLogonDate @script:AdSplat -ErrorAction Stop

    foreach ($u in $users) {
        if (-not $u.LastLogonDate -or $u.LastLogonDate -lt $cutoff) {
            $lastSeen = 'never recorded'
            if ($u.LastLogonDate) { $lastSeen = $u.LastLogonDate.ToString('yyyy-MM-dd') }

            $findings += New-Finding -Category 'Stale Accounts' -Severity 'Medium' `
                -Object $u.SamAccountName -Detail "Enabled account, last logon: $lastSeen" `
                -Recommendation 'Confirm the account is still required; disable or remove if unused.'
        }
    }
    return $findings
}

function Get-AdStaleComputerAccounts {
    <#
    .SYNOPSIS
        Enabled computer accounts with no logon recorded in the configured window.
    
    [CmdletBinding()] param(
        [int]$Days = $script:StaleAccountDays
    )
    $findings = @()
    $cutoff   = (Get-Date).AddDays(-$Days)

    $computers = Get-ADComputer -Filter { Enabled -eq $true } -Properties LastLogonDate, OperatingSystem @script:AdSplat -ErrorAction Stop

    foreach ($c in $computers) {
        if (-not $c.LastLogonDate -or $c.LastLogonDate -lt $cutoff) {
            $lastSeen = 'never recorded'
            if ($c.LastLogonDate) { $lastSeen = $c.LastLogonDate.ToString('yyyy-MM-dd') }
            $os = if ($c.OperatingSystem) { $c.OperatingSystem } else { 'unknown OS' }

            $findings += New-Finding -Category 'Stale Computers' -Severity 'Low' `
                -Object $c.Name -Detail "OS: $os; last logon: $lastSeen" `
                -Recommendation 'Verify the device is still in service; remove stale computer objects to shrink attack surface.'
        }
    }
    return $findings
}

function Get-AdNonExpiringPasswordAccounts {
    <#
    .SYNOPSIS
        Enabled accounts where PasswordNeverExpires is set.
   
    [CmdletBinding()] param()
    $findings = @()

    $accounts = Search-ADAccount -PasswordNeverExpires -UsersOnly @script:AdSplat | Where-Object { $_.Enabled }

    foreach ($a in $accounts) {
        $isPrivileged = $false
        try {
            $adminCount = (Get-ADUser -Identity $a.SamAccountName -Properties AdminCount @script:AdSplat -ErrorAction Stop).AdminCount
            if ($adminCount -eq 1) { $isPrivileged = $true }
        } catch { }

        $severity = if ($isPrivileged) { 'High' } else { 'Medium' }
        $note     = if ($isPrivileged) { ' (PRIVILEGED account)' } else { '' }

        $findings += New-Finding -Category 'Password Policy' -Severity $severity `
            -Object $a.SamAccountName -Detail "PasswordNeverExpires is set on an enabled account$note" `
            -Recommendation 'Disable PasswordNeverExpires; enforce rotation or migrate to a Group Managed Service Account (gMSA).'
    }
    return $findings
}

function Get-AdLockedOutAccounts {
    <#
    .SYNOPSIS
        Accounts currently in a locked-out state.
   
    [CmdletBinding()] param()
    $findings = @()

    $accounts = Search-ADAccount -LockedOut -UsersOnly @script:AdSplat

    foreach ($a in $accounts) {
        $findings += New-Finding -Category 'Account Lockouts' -Severity 'Low' `
            -Object $a.SamAccountName -Detail 'Account is currently locked out' `
            -Recommendation 'Investigate the cause before unlocking; rule out a brute-force or password-spray attempt.'
    }
    return $findings
}

function Get-AdKerberoastableAccounts {
    <#
    .SYNOPSIS
        Enabled accounts with a Service Principal Name set (Kerberoasting targets).
  
    [CmdletBinding()] param()
    $findings = @()

    $users = Get-ADUser -Filter { ServicePrincipalName -like '*' } `
        -Properties ServicePrincipalName, Enabled, PasswordLastSet, AdminCount @script:AdSplat -ErrorAction Stop

    foreach ($u in $users) {
        if (-not $u.Enabled) { continue }
        if ($u.SamAccountName -eq 'krbtgt') { continue }

        $passAgeText = 'unknown'
        if ($u.PasswordLastSet) {
            $passAgeText = "$((New-TimeSpan -Start $u.PasswordLastSet -End (Get-Date)).Days) days"
        }
        $privilegedText = ''
        $severity = 'High'
        if ($u.AdminCount -eq 1) {
            $privilegedText = '; PRIVILEGED (adminCount=1)'
            $severity = 'Critical'
        }

        $findings += New-Finding -Category 'Kerberoasting Exposure' -Severity $severity `
            -Object $u.SamAccountName -Detail "Has SPN(s) set; password age: $passAgeText$privilegedText" `
            -Recommendation 'Migrate to a gMSA, or set a long randomized password and rotate regularly.'
    }
    return $findings
}

function Get-AdAsRepRoastableAccounts {
    <#
    .SYNOPSIS
        Enabled accounts with Kerberos pre-authentication disabled (AS-REP roasting targets).
    
    [CmdletBinding()] param()
    $findings = @()

    $users = Get-ADUser -Filter * -Properties DoesNotRequirePreAuth, Enabled, AdminCount @script:AdSplat -ErrorAction Stop |
        Where-Object { $_.DoesNotRequirePreAuth -and $_.Enabled }

    foreach ($u in $users) {
        $severity = if ($u.AdminCount -eq 1) { 'Critical' } else { 'High' }
        $findings += New-Finding -Category 'AS-REP Roasting Exposure' -Severity $severity `
            -Object $u.SamAccountName -Detail 'Kerberos pre-authentication is disabled (DoesNotRequirePreAuth)' `
            -Recommendation 'Re-enable Kerberos pre-authentication unless there is a documented legacy requirement.'
    }
    return $findings
}

function Get-AdUnconstrainedDelegation {
    <#
    .SYNOPSIS
        Computer and user accounts trusted for unconstrained Kerberos delegation.
        Domain controllers are expected to have this and are excluded.
  
    [CmdletBinding()] param()
    $findings = @()

    $computers = Get-ADComputer -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation, OperatingSystem @script:AdSplat -ErrorAction Stop
    foreach ($c in $computers) {
        if ($c.DistinguishedName -match 'OU=Domain Controllers') { continue }
        $os = if ($c.OperatingSystem) { $c.OperatingSystem } else { 'unknown OS' }

        $findings += New-Finding -Category 'Unconstrained Delegation' -Severity 'Critical' `
            -Object $c.Name -Detail "Non-DC computer trusted for unconstrained delegation. OS: $os" `
            -Recommendation 'Switch to constrained or resource-based constrained delegation; this is a major lateral-movement risk.'
    }

    $users = Get-ADUser -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation @script:AdSplat -ErrorAction Stop
    foreach ($u in $users) {
        $findings += New-Finding -Category 'Unconstrained Delegation' -Severity 'Critical' `
            -Object $u.SamAccountName -Detail 'User account trusted for unconstrained delegation' `
            -Recommendation 'Remove unconstrained delegation from user accounts; this should almost never be required.'
    }
    return $findings
}

function Get-AdAdminCountAnomalies {
    <#
    .SYNOPSIS
        Accounts flagged adminCount=1 (AdminSDHolder-protected) that are no
        longer members of any privileged group - a common hygiene gap.
 
    [CmdletBinding()] param()
    $findings = @()

    $privilegedMembers = New-Object System.Collections.Generic.HashSet[string]
    foreach ($groupName in $script:PrivilegedGroups) {
        try {
            $members = Get-ADGroupMember -Identity $groupName -Recursive @script:AdSplat -ErrorAction Stop
            foreach ($m in $members) { [void]$privilegedMembers.Add($m.SamAccountName) }
        } catch { continue }
    }

    $flagged = Get-ADUser -Filter { AdminCount -eq 1 } -Properties AdminCount, Enabled @script:AdSplat -ErrorAction Stop
    foreach ($u in $flagged) {
        if (-not $privilegedMembers.Contains($u.SamAccountName)) {
            $findings += New-Finding -Category 'AdminSDHolder Anomaly' -Severity 'Medium' `
                -Object $u.SamAccountName -Detail 'adminCount=1 but not currently in any privileged group (AdminSDHolder residue)' `
                -Recommendation 'Reset adminCount to 0 and re-enable ACL inheritance, or confirm protection is still required.'
        }
    }
    return $findings
}

function Get-AdPasswordPolicySummary {
    <#
    .SYNOPSIS
        Summarizes the default domain password policy and any fine-grained
        password policies, flagging weak settings.
   
    [CmdletBinding()] param()
    $findings = @()

    $policy = Get-ADDefaultDomainPasswordPolicy @script:AdSplat -ErrorAction Stop

    if ($policy.MinPasswordLength -lt 14) {
        $findings += New-Finding -Category 'Password Policy' -Severity 'Medium' `
            -Object 'Default Domain Policy' -Detail "Minimum password length is $($policy.MinPasswordLength)" `
            -Recommendation 'Raise minimum length to 14+ characters, ideally paired with MFA.'
    }
    if (-not $policy.ComplexityEnabled) {
        $findings += New-Finding -Category 'Password Policy' -Severity 'Medium' `
            -Object 'Default Domain Policy' -Detail 'Password complexity is NOT enabled' `
            -Recommendation 'Enable complexity, or move to a length-based passphrase policy with breached-password screening.'
    }
    if ($policy.LockoutThreshold -eq 0) {
        $findings += New-Finding -Category 'Password Policy' -Severity 'High' `
            -Object 'Default Domain Policy' -Detail 'Account lockout threshold is disabled (0)' `
            -Recommendation 'Set a lockout threshold (e.g. 5-10 attempts) to slow brute-force / password-spray attacks.'
    }

    $findings += New-Finding -Category 'Password Policy' -Severity 'Info' -Object 'Default Domain Policy' `
        -Detail "MinLength=$($policy.MinPasswordLength); Complexity=$($policy.ComplexityEnabled); LockoutThreshold=$($policy.LockoutThreshold); MaxPasswordAge=$($policy.MaxPasswordAge)"

    try {
        $fgpp = Get-ADFineGrainedPasswordPolicy -Filter * @script:AdSplat -ErrorAction Stop
        foreach ($p in $fgpp) {
            $findings += New-Finding -Category 'Password Policy' -Severity 'Info' `
                -Object $p.Name -Detail "Fine-grained policy: MinLength=$($p.MinPasswordLength), Precedence=$($p.Precedence)"
        }
    } catch { }

    return $findings
}

function Get-AdDomainTrusts {
    <#
    .SYNOPSIS
        Lists configured domain/forest trusts and flags weak SID filtering.
   
    [CmdletBinding()] param()
    $findings = @()

    try {
        $trusts = Get-ADTrust -Filter * @script:AdSplat -ErrorAction Stop
    } catch {
        return $findings
    }

    foreach ($t in $trusts) {
        $severity = 'Info'
        if (-not $t.SIDFilteringQuarantined -and $t.Direction -eq 'BiDirectional') {
            $severity = 'Medium'
        }
        $findings += New-Finding -Category 'Domain Trusts' -Severity $severity `
            -Object $t.Name -Detail "Direction: $($t.Direction); SIDFilteringQuarantined: $($t.SIDFilteringQuarantined); Type: $($t.TrustType)" `
            -Recommendation 'Confirm the trust is still required; ensure SID filtering is enabled on external/forest trusts.'
    }
    return $findings
}

function Get-AdRecentlyCreatedAccounts {
    <#
    .SYNOPSIS
        User accounts created within the configured recent window.
   
    [CmdletBinding()] param(
        [int]$Days = $script:RecentAccountDays
    )
    $findings = @()
    $cutoff   = (Get-Date).AddDays(-$Days)

    $users = Get-ADUser -Filter { whenCreated -ge $cutoff } -Properties whenCreated, Enabled @script:AdSplat -ErrorAction Stop
    foreach ($u in $users) {
        $findings += New-Finding -Category 'Recent Account Creation' -Severity 'Info' `
            -Object $u.SamAccountName -Detail "Created $($u.whenCreated.ToString('yyyy-MM-dd HH:mm')); Enabled: $($u.Enabled)" `
            -Recommendation 'Confirm creation was authorized and tied to a change/onboarding ticket.'
    }
    return $findings
}

function Get-AdExpiringAccounts {
    <#
    .SYNOPSIS
        Enabled accounts due to expire within the configured window.
    
    [CmdletBinding()] param(
        [int]$Days = $script:ExpiringSoonDays
    )
    $findings = @()
    $window   = (Get-Date).AddDays($Days)
    $now      = Get-Date

    $users = Get-ADUser -Filter { Enabled -eq $true } -Properties AccountExpirationDate @script:AdSplat -ErrorAction Stop |
        Where-Object { $_.AccountExpirationDate -and $_.AccountExpirationDate -ge $now -and $_.AccountExpirationDate -le $window }

    foreach ($u in $users) {
        $findings += New-Finding -Category 'Expiring Accounts' -Severity 'Info' `
            -Object $u.SamAccountName -Detail "Expires $($u.AccountExpirationDate.ToString('yyyy-MM-dd'))" `
            -Recommendation 'Confirm expiry is intentional (contractor/temp access); extend or offboard as appropriate.'
    }
    return $findings
}

function Invoke-AdFullSecurityAudit {
    <#
    .SYNOPSIS
        Runs every audit module and returns the combined finding set.
   
    [CmdletBinding()] param()

    $modules = [ordered]@{
        'Privileged Group Membership' = { Get-AdPrivilegedGroupAudit }
        'Stale User Accounts'         = { Get-AdStaleUserAccounts }
        'Stale Computer Accounts'     = { Get-AdStaleComputerAccounts }
        'Non-Expiring Passwords'      = { Get-AdNonExpiringPasswordAccounts }
        'Locked Out Accounts'         = { Get-AdLockedOutAccounts }
        'Kerberoasting Exposure'      = { Get-AdKerberoastableAccounts }
        'AS-REP Roasting Exposure'    = { Get-AdAsRepRoastableAccounts }
        'Unconstrained Delegation'    = { Get-AdUnconstrainedDelegation }
        'AdminSDHolder Anomalies'     = { Get-AdAdminCountAnomalies }
        'Password Policy'             = { Get-AdPasswordPolicySummary }
        'Domain Trusts'               = { Get-AdDomainTrusts }
        'Recently Created Accounts'   = { Get-AdRecentlyCreatedAccounts }
        'Expiring Accounts'           = { Get-AdExpiringAccounts }
    }

    $allFindings = @()
    $total = $modules.Count
    $i = 0

    foreach ($name in $modules.Keys) {
        $i++
        Write-Progress -Activity 'Running AD Security Audit' -Status $name -PercentComplete (($i / $total) * 100)
        try {
            $allFindings += & $modules[$name]
        } catch {
            $allFindings += New-Finding -Category $name -Severity 'Low' -Object 'Module Error' -Detail $_.Exception.Message
        }
    }
    Write-Progress -Activity 'Running AD Security Audit' -Completed
    return $allFindings
}

#endregion

#region Output / Export

function Show-FindingsTable {
    <#
    .SYNOPSIS
        Prints findings to the console, color-coded and sorted by severity.
    
    [CmdletBinding()] param(
        [Parameter(Mandatory, ValueFromPipeline)][object[]]$Findings
    )
    begin { $buffer = @() }
    process { $buffer += $Findings }
    end {
        if ($buffer.Count -eq 0) {
            Write-Host '  No findings in this category.' -ForegroundColor Green
            return
        }
        $order  = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }
        $sorted = $buffer | Sort-Object { $order[$_.Severity] }

        foreach ($f in $sorted) {
            $color = Get-SeverityColor -Severity $f.Severity
            Write-Host ('  [{0,-8}] {1,-22} {2}' -f $f.Severity, $f.Object, $f.Detail) -ForegroundColor $color
        }
    }
}

function Show-AuditSummary {
    <#
    .SYNOPSIS
        Prints a severity count summary for a finding set.
    
    [CmdletBinding()] param(
        [Parameter(Mandatory)][object[]]$Findings
    )
    $bySeverity = $Findings | Group-Object Severity
    Write-Host ''
    Write-Host '  --- RISK SUMMARY ---' -ForegroundColor White
    foreach ($sev in 'Critical', 'High', 'Medium', 'Low', 'Info') {
        $match = $bySeverity | Where-Object Name -eq $sev
        $count = if ($match) { $match.Count } else { 0 }
        $color = Get-SeverityColor -Severity $sev
        Write-Host ('  {0,-8}: {1}' -f $sev, $count) -ForegroundColor $color
    }
    Write-Host ''
}
#>
function Export-AdSecurityReport {
    <#
    .SYNOPSIS
        Exports a finding set to a styled, self-contained HTML report.
    #>
    [CmdletBinding()] param(
        [Parameter(Mandatory)][object[]]$Findings,
        [string]$Path = (Join-Path -Path (Get-Location) -ChildPath "AD-Security-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').html")
    )

    $order = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }
    $sortedFindings = $Findings | Sort-Object { $order[$_.Severity] }, Category

    $rowsHtml = ($sortedFindings | ForEach-Object {
        $cssClass = 'sev-' + $_.Severity.ToLower()
        "<tr class='$cssClass'><td>$($_.Severity)</td><td>$($_.Category)</td><td>$($_.Object)</td><td>$($_.Detail)</td><td>$($_.Recommendation)</td></tr>"
    }) -join "`n"

    $summaryHtml = ($Findings | Group-Object Severity | ForEach-Object {
        "<span class='badge sev-$($_.Name.ToLower())'>$($_.Name): $($_.Count)</span>"
    }) -join ' '

    $connection = if ($script:AdSplat.ContainsKey('Server')) { $script:AdSplat['Server'] } else { 'default (current user / DNS-located DC)' }
    $hostName  = [System.Net.Dns]::GetHostName()
    $generated = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    $html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset='utf-8'>
<title>AD Security Console Report</title>
<style>
  body { font-family: Consolas, 'Courier New', monospace; background:#0d1117; color:#c9d1d9; margin:0; padding:30px; }
  h1 { color:#58a6ff; }
  .meta { color:#8b949e; margin-bottom:20px; }
  table { width:100%; border-collapse: collapse; margin-top:20px; }
  th, td { padding:8px 12px; border-bottom:1px solid #30363d; text-align:left; vertical-align:top; }
  th { background:#161b22; color:#58a6ff; }
  tr.sev-critical { background: rgba(248,81,73,0.12); }
  tr.sev-high     { background: rgba(219,109,255,0.10); }
  tr.sev-medium   { background: rgba(210,153,34,0.10); }
  tr.sev-low      { background: rgba(56,189,248,0.08); }
  tr.sev-info     { background: rgba(63,185,80,0.06); }
  .badge { display:inline-block; padding:4px 10px; border-radius:4px; margin-right:8px; font-weight:bold; }
  .badge.sev-critical { background:#f85149; color:#0d1117; }
  .badge.sev-high     { background:#db6dff; color:#0d1117; }
  .badge.sev-medium   { background:#d29922; color:#0d1117; }
  .badge.sev-low      { background:#38bdf8; color:#0d1117; }
  .badge.sev-info     { background:#3fb950; color:#0d1117; }
</style>
</head>
<body>
  <h1>AD SECURITY CONSOLE &mdash; Audit Report</h1>
  <div class='meta'>Generated $generated on $hostName (management host) &middot; queried via: $connection</div>
  <div>$summaryHtml</div>
  <table>
    <tr><th>Severity</th><th>Category</th><th>Object</th><th>Detail</th><th>Recommendation</th></tr>
    $rowsHtml
  </table>
</body>
</html>
"@

    $html | Out-File -FilePath $Path -Encoding utf8
    return $Path
}

#endregion

Export-ModuleMember -Function `
    Set-AdConnection, `
    Get-AdConnection, `
    Test-AdConnectivity, `
    Test-AdModuleAvailable, `
    Get-AdPrivilegedGroupAudit, `
    Get-AdStaleUserAccounts, `
    Get-AdStaleComputerAccounts, `
    Get-AdNonExpiringPasswordAccounts, `
    Get-AdLockedOutAccounts, `
    Get-AdKerberoastableAccounts, `
    Get-AdAsRepRoastableAccounts, `
    Get-AdUnconstrainedDelegation, `
    Get-AdAdminCountAnomalies, `
    Get-AdPasswordPolicySummary, `
    Get-AdDomainTrusts, `
    Get-AdRecentlyCreatedAccounts, `
    Get-AdExpiringAccounts, `
    Invoke-AdFullSecurityAudit, `
    Show-FindingsTable, `
    Show-AuditSummary, `
    Export-AdSecurityReport, `
    Get-SeverityColor
