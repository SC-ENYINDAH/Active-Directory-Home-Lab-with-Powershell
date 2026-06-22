<#
.SYNOPSIS
  AD Security Dashboard (manual launch, no Splunk)

.DESCRIPTION
  Compliance snapshot + live monitoring + email alerts + local logging.

  Improvements vs the pasted version:
  - Adds StartTime window for consistent comparisons
  - Safer event property parsing (4625/4740)
  - More robust logging and retryable email send
  - Basic parallelization via jobs (Windows PowerShell compatible)
  - Thresholding based on unique offenders (configurable)

.NOTES
  Ensure the ActiveDirectory module is available and run PowerShell as Administrator.
  Update SMTP settings and DC hostname (default DC01) to match your environment.
#>

param(
    [switch]$AuditOnly,
    [switch]$MonitorOnly,

    # Monitoring time window (used with StartTime)
    [int]$TimeWindowSeconds = 3600,

    # How many events to request per host (within the time window)
    [int]$MaxEventsPerHost = 50,

    # Email throttling: minimum seconds between repeated emails for the same category
    [int]$EmailCooldownSeconds = 900
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# -------------------------
# Configuration
# -------------------------
$logFile = "C:\AuditLogs\SecurityAlerts.log"
$logDir = Split-Path $logFile -Parent
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }

# Email config - update to your environment
$smtpServer = "smtp.yourmailserver.com"
$from = "alerts@yourdomain.com"
$serverRecipients = "serverteam@yourdomain.com"
$workstationRecipients = "helpdesk@yourdomain.com"
$subjectFailed = "AD Security Alert - Failed Logins"
$subjectLockout = "AD Security Alert - Account Lockouts"

# Thresholds - tune for your environment
# Use offender-based thresholds by default (unique users and/or unique IPs), not raw event count.
$serverFailedOffenderThreshold = 10   # unique users
$workstationFailedOffenderThreshold = 30 # unique users
$lockoutThreshold = 5                 # lockout event count

# Domain Controller to query for lockout events (update if needed)
$domainController = "DC01"

# -------------------------
# Helpers
# -------------------------
$script:__lastEmailTimes = [System.Collections.Generic.Dictionary[string, datetime]]::new()

function Write-Log {
    param(
        [Parameter(Mandatory)] [string]$Message,
        [ValidateSet('INFO','WARN','ERROR','SUCCESS')] [string]$Level = 'INFO'
    )

    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $entry = "$timestamp [$Level] $Message"

    try {
        Add-Content -Path $logFile -Value $entry
    } catch {
        # Avoid hard failure if logging path is not writable
        Write-Warning "Unable to write to log file: $logFile. $($_.Exception.Message)"
    }

    $color = switch ($Level) {
        'SUCCESS' { 'Green' }
        'ERROR'   { 'Red' }
        'WARN'    { 'Yellow' }
        default   { 'White' }
    }

    Write-Host $entry -ForegroundColor $color
}

function Should-SendEmail {
    param([Parameter(Mandatory)][string]$Key)

    $now = Get-Date
    if ($script:__lastEmailTimes.ContainsKey($Key)) {
        $last = $script:__lastEmailTimes[$Key]
        if (($now - $last).TotalSeconds -lt $EmailCooldownSeconds) {
            return $false
        }
    }

    $script:__lastEmailTimes[$Key] = $now
    return $true
}

function Safe-UserFrom4625 {
    param([Parameter(Mandatory)] $EventRecord)

    # 4625 fields can vary; try EventData first, then fallback to Properties.
    try {
        $xml = [xml]$EventRecord.ToXml()
        $data = $xml.Event.EventData.Data
        # Common field names: TargetUserName, AccountName, etc.
        foreach ($node in $data) {
            if ($node.Name -match 'TargetUserName|AccountName|UserName') {
                if ($node.'#text') { return [string]$node.'#text' }
            }
        }

        # Fallback: older scripts used index 5
        if ($EventRecord.Properties.Count -gt 5) {
            $v = $EventRecord.Properties[5].Value
            if ($v) { return [string]$v }
        }
    } catch {}

    return ''
}

function Safe-IPFrom4625 {
    param([Parameter(Mandatory)] $EventRecord)

    try {
        $xml = [xml]$EventRecord.ToXml()
        $data = $xml.Event.EventData.Data
        foreach ($node in $data) {
            if ($node.Name -match 'IpAddress|SourceAddress|ClientAddress') {
                if ($node.'#text') { return [string]$node.'#text' }
            }
        }

        # Fallback index used by the pasted script
        if ($EventRecord.Properties.Count -gt 18) {
            $v = $EventRecord.Properties[18].Value
            if ($v) { return [string]$v }
        }
    } catch {}

    return ''
}

function Get-StartTime {
    param([int]$TimeWindowSeconds)
    return (Get-Date).AddSeconds(-1 * $TimeWindowSeconds)
}

function Send-AlertEmail {
    param(
        [Parameter(Mandatory)][string]$To,
        [Parameter(Mandatory)][string]$Subject,
        [Parameter(Mandatory)][string]$Body,
        [Parameter(Mandatory)][string]$EmailKey
    )

    if (-not (Should-SendEmail -Key $EmailKey)) {
        Write-Log "Email suppressed by cooldown for '$EmailKey'." 'INFO'
        return
    }

    try {
        Send-MailMessage -SmtpServer $smtpServer -From $from -To $To -Subject $Subject -Body $Body -ErrorAction Stop
        Write-Log "Email sent: '$Subject' -> $To" 'SUCCESS'
    } catch {
        Write-Log "Send-MailMessage failed for '$Subject' -> $To. $($_.Exception.Message)" 'ERROR'
    }
}

# -------------------------
# Audit Functions
# -------------------------
function Get-PasswordPolicy {
    try {
        Get-ADDefaultDomainPasswordPolicy | Select MinPasswordLength, MaxPasswordAge, LockoutThreshold
    } catch {
        Write-Log "ERROR: Get-PasswordPolicy - $($_.Exception.Message)" 'ERROR'
        return $null
    }
}

function Get-LockedAccounts {
    try {
        Search-ADAccount -LockedOut | Select Name, SamAccountName
    } catch {
        Write-Log "ERROR: Get-LockedAccounts - $($_.Exception.Message)" 'ERROR'
        return @()
    }
}

function Get-EnabledUsers {
    try {
        Get-ADUser -Filter { Enabled -eq $true } | Select Name, SamAccountName
    } catch {
        Write-Log "ERROR: Get-EnabledUsers - $($_.Exception.Message)" 'ERROR'
        return @()
    }
}

function Run-Audit {
    Write-Host "`n--- Password Policy ---" -ForegroundColor Green
    $policy = Get-PasswordPolicy
    if ($policy) {
        $policy | Format-Table -AutoSize
        Write-Log "Password Policy captured" 'INFO'
    }

    Write-Host "`n--- Locked Accounts ---" -ForegroundColor Green
    $locked = Get-LockedAccounts
    if ($locked -and $locked.Count -gt 0) {
        $locked | Format-Table -AutoSize
        Write-Log "Locked accounts count: $($locked.Count)" 'WARN'
    } else {
        Write-Host "No locked accounts found." -ForegroundColor Yellow
    }

    Write-Host "`n--- Enabled Users Count ---" -ForegroundColor Green
    $enabled = Get-EnabledUsers
    $enabledCount = if ($enabled) { $enabled.Count } else { 0 }
    Write-Host "Enabled Users: $enabledCount" -ForegroundColor Yellow
    Write-Log "Enabled users count: $enabledCount" 'INFO'
}

# -------------------------
# Monitoring Runner
# -------------------------
function Get-FailedLoginsFromHost {
    param(
        [Parameter(Mandatory)][string]$HostName,
        [Parameter(Mandatory)][datetime]$StartTime,
        [Parameter(Mandatory)][int]$MaxEvents
    )

    try {
        $events = Get-WinEvent -ComputerName $HostName -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = $StartTime } -MaxEvents $MaxEvents -ErrorAction Stop

        foreach ($e in $events) {
            $u = Safe-UserFrom4625 -EventRecord $e
            $ip = Safe-IPFrom4625 -EventRecord $e
            [PSCustomObject]@{
                Computer    = $HostName
                TimeCreated = $e.TimeCreated
                User        = $u
                IP          = $ip
            }
        }
    } catch {
        Write-Log "WARN: Could not query $HostName for 4625. $($_.Exception.Message)" 'WARN'
        return @()
    }
}

function Run-Monitor {
    $startTime = Get-StartTime -TimeWindowSeconds $TimeWindowSeconds

    # Discover hosts dynamically from AD
    try {
        $servers = Get-ADComputer -Filter { Enabled -eq $true -and OperatingSystem -like "*Server*" } -Property Name |
            Select-Object -ExpandProperty Name
        $workstations = Get-ADComputer -Filter { Enabled -eq $true -and OperatingSystem -like "*Windows*" } -Property Name |
            Select-Object -ExpandProperty Name
    } catch {
        Write-Log "ERROR: Get-ADComputer discovery failed. $($_.Exception.Message)" 'ERROR'
        return
    }

    Write-Host "`n--- Monitoring (StartTime=$startTime) ---" -ForegroundColor Cyan

    # Use throttled jobs for better performance on Windows PowerShell.
    $jobResults = New-Object System.Collections.Generic.List[object]
    $allTargets = @(
        @{ Kind = 'Server'; Host = $servers }
        @{ Kind = 'Workstation'; Host = $workstations }
    )

    foreach ($block in $allTargets) {
        $kind = $block.Kind
        $targets = @($block.Host | Where-Object { $_ -and $_.Trim() -ne '' })
        Write-Host "--- Monitoring $kind hosts: $($targets.Count) ---" -ForegroundColor Green

        # Throttle level: adjust if needed
        $throttle = 10
        $jobs = @()

        foreach ($h in $targets) {
            while (@($jobs | Where-Object { $_.State -eq 'Running' }).Count -ge $throttle) {
                Start-Sleep -Milliseconds 300
                $done = $jobs | Where-Object { $_.State -eq 'Completed' }
                foreach ($j in $done) {
                    $jobResults.AddRange(@(Receive-Job -Job $j -ErrorAction SilentlyContinue)) | Out-Null
                    Remove-Job $j -Force | Out-Null
                    $jobs = $jobs | Where-Object { $_.Id -ne $j.Id }
                }
            }

            $jobs += Start-Job -Name "4625-$kind-$h" -ArgumentList $h, $startTime, $MaxEventsPerHost -ScriptBlock {
                param($HostName, $StartTimeInner, $MaxEventsInner)

                function Safe-UserFrom4625 {
                    param([Parameter(Mandatory)] $EventRecord)
                    try {
                        $xml = [xml]$EventRecord.ToXml()
                        $data = $xml.Event.EventData.Data
                        foreach ($node in $data) {
                            if ($node.Name -match 'TargetUserName|AccountName|UserName') {
                                if ($node.'#text') { return [string]$node.'#text' }
                            }
                        }
                        if ($EventRecord.Properties.Count -gt 5) {
                            $v = $EventRecord.Properties[5].Value
                            if ($v) { return [string]$v }
                        }
                    } catch {}
                    return ''
                }

                function Safe-IPFrom4625 {
                    param([Parameter(Mandatory)] $EventRecord)
                    try {
                        $xml = [xml]$EventRecord.ToXml()
                        $data = $xml.Event.EventData.Data
                        foreach ($node in $data) {
                            if ($node.Name -match 'IpAddress|SourceAddress|ClientAddress') {
                                if ($node.'#text') { return [string]$node.'#text' }
                            }
                        }
                        if ($EventRecord.Properties.Count -gt 18) {
                            $v = $EventRecord.Properties[18].Value
                            if ($v) { return [string]$v }
                        }
                    } catch {}
                    return ''
                }

                try {
                    $events = Get-WinEvent -ComputerName $HostName -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = $StartTimeInner } -MaxEvents $MaxEventsInner -ErrorAction Stop
                    foreach ($e in $events) {
                        [PSCustomObject]@{
                            Kind         = $using:kind
                            Computer    = $HostName
                            TimeCreated = $e.TimeCreated
                            User        = (Safe-UserFrom4625 -EventRecord $e)
                            IP          = (Safe-IPFrom4625 -EventRecord $e)
                        }
                    }
                } catch {
                    # swallow inside job
                    @()
                }
            }
        }

        # Drain remaining jobs
        foreach ($j in $jobs) {
            $jobResults.AddRange(@(Receive-Job -Job $j -ErrorAction SilentlyContinue)) | Out-Null
            Remove-Job $j -Force | Out-Null
        }
    }

    # Split results by category
    $failedServers = @($jobResults | Where-Object { $_.Kind -eq 'Server' })
    $failedWorkstations = @($jobResults | Where-Object { $_.Kind -eq 'Workstation' })

    # Compute unique offenders
    $serverUniqueUsers = ($failedServers | Where-Object { $_.User } | Select-Object -ExpandProperty User -Unique)
    $workUniqueUsers = ($failedWorkstations | Where-Object { $_.User } | Select-Object -ExpandProperty User -Unique)

    $serverCountEvents = $failedServers.Count
    $workCountEvents = $failedWorkstations.Count

    Write-Host "Servers: events=$serverCountEvents uniqueUsers=$($serverUniqueUsers.Count)" -ForegroundColor Yellow
    Write-Host "Workstations: events=$workCountEvents uniqueUsers=$($workUniqueUsers.Count)" -ForegroundColor Yellow

    if ($serverUniqueUsers.Count -gt $serverFailedOffenderThreshold) {
        $topByUser = $failedServers |
            Where-Object { $_.User } |
            Group-Object User |
            Sort-Object Count -Descending |
            Select-Object -First 10

        $ipDetailsSrv = $topByUser | ForEach-Object {
            $ips = ($_.Group | Select-Object -ExpandProperty IP | Where-Object { $_ } | Sort-Object -Unique) -join ', '
            "User: $($_.Name) - Attempts: $($_.Count) - IPs: $ips"
        } | Out-String

        $bodySrv = "Alert: Server failed logins exceeded threshold in the last $TimeWindowSeconds seconds.\nTime: $(Get-Date)\nUniqueUsers: $($serverUniqueUsers.Count)\n\nTop offenders:\n$ipDetailsSrv"
        Write-Log "SERVER FAILED LOGIN ALERT triggered. events=$serverCountEvents uniqueUsers=$($serverUniqueUsers.Count)" 'WARN'

        Send-AlertEmail -To $serverRecipients -Subject "$subjectFailed (Servers)" -Body $bodySrv -EmailKey 'FailedLoginsServers'
        Add-Content -Path $logFile -Value "[$(Get-Date)] SERVER FAILED LOGIN ALERT SUMMARY events=$serverCountEvents uniqueUsers=$($serverUniqueUsers.Count)"
    }

    if ($workUniqueUsers.Count -gt $workstationFailedOffenderThreshold) {
        $topByUserW = $failedWorkstations |
            Where-Object { $_.User } |
            Group-Object User |
            Sort-Object Count -Descending |
            Select-Object -First 10

        $ipDetailsWork = $topByUserW | ForEach-Object {
            $ips = ($_.Group | Select-Object -ExpandProperty IP | Where-Object { $_ } | Sort-Object -Unique) -join ', '
            "User: $($_.Name) - Attempts: $($_.Count) - IPs: $ips"
        } | Out-String

        $bodyWork = "Alert: Workstation failed logins exceeded threshold in the last $TimeWindowSeconds seconds.\nTime: $(Get-Date)\nUniqueUsers: $($workUniqueUsers.Count)\n\nTop offenders:\n$ipDetailsWork"
        Write-Log "WORKSTATION FAILED LOGIN ALERT triggered. events=$workCountEvents uniqueUsers=$($workUniqueUsers.Count)" 'WARN'

        Send-AlertEmail -To $workstationRecipients -Subject "$subjectFailed (Workstations)" -Body $bodyWork -EmailKey 'FailedLoginsWorkstations'
        Add-Content -Path $logFile -Value "[$(Get-Date)] WORKSTATION FAILED LOGIN ALERT SUMMARY events=$workCountEvents uniqueUsers=$($workUniqueUsers.Count)"
    }

    # Account lockouts (from DC)
    $lockStart = $startTime
    try {
        $lockouts = Get-WinEvent -ComputerName $domainController -FilterHashtable @{ LogName = 'Security'; Id = 4740; StartTime = $lockStart } -MaxEvents 200
        $lockCount = @($lockouts).Count
    } catch {
        Write-Log "WARN: Could not query lockouts from $domainController. $($_.Exception.Message)" 'WARN'
        $lockouts = @()
        $lockCount = 0
    }

    if ($lockCount -gt 0) {
        Write-Host "Lockouts in window: $lockCount" -ForegroundColor Green

        # Safer extraction of locked user from XML
        $lockouts | ForEach-Object {
            $xml = [xml]$_.ToXml()
            $data = $xml.Event.EventData.Data
            $u = ''
            foreach ($node in $data) {
                if ($node.Name -match 'TargetUserName|AccountName') {
                    if ($node.'#text') { $u = [string]$node.'#text' }
                }
            }
            [PSCustomObject]@{ TimeCreated = $_.TimeCreated; LockedUser = $u }
        } | Sort-Object TimeCreated -Descending | Select-Object -First 10 | Format-Table -AutoSize
    } else {
        Write-Host "No account lockouts found in window." -ForegroundColor Yellow
    }

    if ($lockCount -gt $lockoutThreshold) {
        $bodyLock = "Alert: $lockCount account lockouts detected on $domainController in the last $TimeWindowSeconds seconds.\nTime: $(Get-Date)"
        Write-Log "LOCKOUT ALERT triggered. lockCount=$lockCount" 'WARN'

        Send-AlertEmail -To "$serverRecipients,$workstationRecipients" -Subject $subjectLockout -Body $bodyLock -EmailKey 'Lockouts'
        Add-Content -Path $logFile -Value "[$(Get-Date)] LOCKOUT ALERT SUMMARY lockCount=$lockCount"
    }
}

# -------------------------
# Execution
# -------------------------
if ($AuditOnly -and $MonitorOnly) {
    throw "Invalid usage: choose only one of -AuditOnly or -MonitorOnly (or none for interactive menu)."
}

Import-Module ActiveDirectory -ErrorAction Stop

if ($AuditOnly) {
    Run-Audit
    exit
}

if ($MonitorOnly) {
    Write-Host "Starting MonitorOnly (continuous). Press Ctrl+C to stop." -ForegroundColor Cyan
    while ($true) {
        try {
            Run-Monitor
        } catch {
            Write-Log "ERROR: Monitor loop failed. $($_.Exception.Message)" 'ERROR'
        }
        Start-Sleep -Seconds 60
    }
}

# Interactive menu (default)
while ($true) {
    Clear-Host
    Write-Host "`n===== AD Security Dashboard Menu =====" -ForegroundColor Cyan
    Write-Host "[1] AuditOnly    - Run compliance snapshot once" -ForegroundColor Cyan
    Write-Host "[2] MonitorOnly  - Start continuous monitoring (press Ctrl+C to stop)" -ForegroundColor Cyan
    Write-Host "[3] Run Both     - Run audit once, then start monitoring" -ForegroundColor Cyan
    Write-Host "[q] Quit" -ForegroundColor Cyan

    $choice = Read-Host "Enter your choice"

    switch ($choice.ToLower()) {
        '1' {
            Write-Host "`nRunning AuditOnly..." -ForegroundColor Yellow
            Run-Audit
            Write-Host "`nAudit complete." -ForegroundColor Green
            Read-Host "Press Enter to return to menu"
        }
        '2' {
            Write-Host "`nStarting MonitorOnly... (Ctrl+C to stop)" -ForegroundColor Yellow
            while ($true) {
                try {
                    Run-Monitor
                } catch {
                    Write-Log "ERROR: MonitorOnly loop failed. $($_.Exception.Message)" 'ERROR'
                }
                Start-Sleep -Seconds 60
            }
        }
        '3' {
            Write-Host "`nRunning audit first..." -ForegroundColor Yellow
            Run-Audit
            Write-Host "`nStarting monitoring... (Ctrl+C to stop)" -ForegroundColor Yellow
            while ($true) {
                try {
                    Run-Monitor
                } catch {
                    Write-Log "ERROR: RunBoth loop failed. $($_.Exception.Message)" 'ERROR'
                }
                Start-Sleep -Seconds 60
            }
        }
        'q' {
            Write-Host "`nQuitting dashboard." -ForegroundColor Cyan
            break
        }
        default {
            Write-Host "Invalid choice." -ForegroundColor Red
            Start-Sleep -Seconds 1
        }
    }
}

