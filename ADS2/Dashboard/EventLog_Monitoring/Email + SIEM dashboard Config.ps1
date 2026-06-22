# Email + SIEM config
$smtpServer = "smtp.duck.com"
$from = "alerts@yourdomain.com"
$serverRecipients = "serverteam@yourdomain.com"
$workstationRecipients = "helpdesk@yourdomain.com"
$subjectFailed = "AD Security Alert - Failed Logins"
$subjectLockout = "AD Security Alert - Account Lockouts"
$logFile = "C:\AuditLogs\SecurityAlerts.log"


# Thresholds
$serverFailedThreshold = 10
$workstationFailedThreshold = 30
$lockoutThreshold = 5

while ($true) {
    Clear-Host
    Write-Host "===== AD Security Dashboard =====" -ForegroundColor Cyan
    Write-Host "Updated: $(Get-Date)" -ForegroundColor Yellow

    # Dynamically fetch servers and workstations
    $servers = Get-ADComputer -Filter {Enabled -eq $true -and OperatingSystem -like "*Server*"} -Property Name | Select-Object -ExpandProperty Name
    $workstations = Get-ADComputer -Filter {Enabled -eq $true -and OperatingSystem -like "*Windows*"} -Property Name | Select-Object -ExpandProperty Name

    Write-Host "`n--- Monitoring Servers ---" -ForegroundColor Green
    $servers | Format-Table
    Write-Host "`n--- Monitoring Workstations ---" -ForegroundColor Green
    $workstations | Format-Table

    # Collect failed logins from servers
    $serverFailed = @()
    foreach ($srv in $servers) {
        try {
            $events = Get-WinEvent -ComputerName $srv -FilterHashtable @{LogName='Security';ID=4625} -MaxEvents 20
            $events | ForEach-Object {
                $serverFailed += [PSCustomObject]@{
                    Computer = $srv
                    TimeCreated = $_.TimeCreated
                    User = $_.Properties[5].Value
                    IP = $_.Properties[18].Value
                }
            }
        } catch {
            Write-Host "Could not query $srv" -ForegroundColor DarkRed
        }
    }

    $serverCount = $serverFailed.Count
    Write-Host "`nServer Failed Logins: $serverCount" -ForegroundColor Yellow
    if ($serverCount -gt $serverFailedThreshold) {
        Write-Host "WARNING: Server failed logins exceeded threshold ($serverCount)!" -ForegroundColor Red

        $topSrvFailed = $serverFailed | Group-Object User | Sort-Object Count -Descending | Select-Object -First 10
        $detailsSrv = $topSrvFailed | ForEach-Object { "User: $($_.Name) - Attempts: $($_.Count)" } | Out-String

        # Include IP addresses in email table
        $ipDetailsSrv = $serverFailed | Group-Object User | ForEach-Object {
            $user = $_.Name
            $ips = ($_.Group | Select-Object -ExpandProperty IP | Sort-Object -Unique) -join ", "
            "User: $user - Attempts: $($_.Count) - IPs: $ips"
        } | Out-String

        $bodySrv = "Alert: $serverCount failed logins detected on servers.`nTime: $(Get-Date)`nTop offenders:`n$ipDetailsSrv"
        Send-MailMessage -SmtpServer $smtpServer -From $from -To $serverRecipients -Subject "$subjectFailed (Servers)" -Body $bodySrv
        Add-Content -Path $logFile -Value "[$(Get-Date)] SERVER FAILED LOGIN ALERT: $serverCount attempts.`n$ipDetailsSrv"
        $payload = @{event=$bodySrv} | ConvertTo-Json
        Invoke-RestMethod -Method Post -Uri $siemEndpoint -Headers @{Authorization="Splunk $siemToken"} -Body $payload
    }

    # Collect failed logins from workstations
    $workFailed = @()
    foreach ($ws in $workstations) {
        try {
            $events = Get-WinEvent -ComputerName $ws -FilterHashtable @{LogName='Security';ID=4625} -MaxEvents 20
            $events | ForEach-Object {
                $workFailed += [PSCustomObject]@{
                    Computer = $ws
                    TimeCreated = $_.TimeCreated
                    User = $_.Properties[5].Value
                    IP = $_.Properties[18].Value
                }
            }
        } catch {
            Write-Host "Could not query $ws" -ForegroundColor DarkRed
        }
    }

    $workCount = $workFailed.Count
    Write-Host "`nWorkstation Failed Logins: $workCount" -ForegroundColor Yellow
    if ($workCount -gt $workstationFailedThreshold) {
        Write-Host "WARNING: Workstation failed logins exceeded threshold ($workCount)!" -ForegroundColor Red

        $topWorkFailed = $workFailed | Group-Object User | Sort-Object Count -Descending | Select-Object -First 10
        $ipDetailsWork = $workFailed | Group-Object User | ForEach-Object {
            $user = $_.Name
            $ips = ($_.Group | Select-Object -ExpandProperty IP | Sort-Object -Unique) -join ", "
            "User: $user - Attempts: $($_.Count) - IPs: $ips"
        } | Out-String

        $bodyWork = "Alert: $workCount failed logins detected on workstations.`nTime: $(Get-Date)`nTop offenders:`n$ipDetailsWork"
        Send-MailMessage -SmtpServer $smtpServer -From $from -To $workstationRecipients -Subject "$subjectFailed (Workstations)" -Body $bodyWork
        Add-Content -Path $logFile -Value "[$(Get-Date)] WORKSTATION FAILED LOGIN ALERT: $workCount attempts.`n$ipDetailsWork"
        $payload = @{event=$bodyWork} | ConvertTo-Json
        Invoke-RestMethod -Method Post -Uri $siemEndpoint -Headers @{Authorization="Splunk $siemToken"} -Body $payload
    }

    # Account Lockouts (DC only)
    Write-Host "`n--- Account Lockouts (4740) ---" -ForegroundColor Green
    $lockouts = Get-WinEvent -ComputerName "DC01" -FilterHashtable @{LogName='Security';ID=4740} -MaxEvents 10
    $lockouts | Select TimeCreated, @{Name='LockedUser';Expression={$_.Properties[0].Value}} | Format-Table -AutoSize
    $lockCount = $lockouts.Count
    if ($lockCount -gt $lockoutThreshold) {
        Write-Host "WARNING: Lockouts exceeded threshold ($lockCount)!" -ForegroundColor Red
        $bodyLock = "Alert: $lockCount account lockouts detected.`nTime: $(Get-Date)"
        Send-MailMessage -SmtpServer $smtpServer -From $from -To "$serverRecipients,$workstationRecipients" -Subject $subjectLockout -Body $bodyLock
        Add-Content -Path $logFile -Value "[$(Get-Date)] LOCKOUT ALERT: $lockCount accounts locked out."
        $payload = @{event=$bodyLock} | ConvertTo-Json
        Invoke-RestMethod -Method Post -Uri $siemEndpoint -Headers @{Authorization="Splunk $siemToken"} -Body $payload
    }

    Start-Sleep -Seconds 60
}
