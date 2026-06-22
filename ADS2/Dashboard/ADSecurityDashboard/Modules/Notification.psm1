Set-StrictMode -Version Latest

function Test-AlertCooldown {

    param(
        [object]$State
    )

    if(
        [string]::IsNullOrWhiteSpace(
            $State.LastAlert
        )
    )
    {
        return $true
    }

    $Minutes =
        (
            (Get-Date) -
            ([datetime]$State.LastAlert)
        ).TotalMinutes

    return (
        $Minutes -ge
        $Global:Config.Monitoring.AlertCooldownMinutes
    )
}

function Update-AlertTime {

    param(
        [object]$State
    )

    $State.LastAlert =
        (Get-Date).ToString("o")

    Save-State `
        -State $State `
        -Path $Global:StateFile
}

function Send-EmailAlert {

    param(

        [string]$Subject,

        [string]$Body
    )

    try {

        $Client =
            New-Object System.Net.Mail.SmtpClient(
                $Global:Config.Email.SMTPServer,
                $Global:Config.Email.Port
            )

        $Client.EnableSsl = $true

        $Message =
            New-Object System.Net.Mail.MailMessage

        $Message.From =
            $Global:Config.Email.From

        foreach(
            $Recipient in
            $Global:Config.Email.To
        )
        {
            $Message.To.Add(
                $Recipient
            )
        }

        $Message.Subject =
            $Subject

        $Message.Body =
            $Body

        $Client.Send(
            $Message
        )
    }
    catch {

        Write-Log `
            -Level "ERROR" `
            -Message $_.Exception.Message
    }
}

function Send-SecurityAlert {

    param(

        [object]$ThreatReport,

        [object]$State
    )

    if(
        -not(
            Test-AlertCooldown $State
        )
    )
    {
        return
    }

    $Subject =
        "AD Security Alert [$($ThreatReport.Severity)]"

    $Body =
@"
Threat Severity: $($ThreatReport.Severity)

Threat Score: $($ThreatReport.ThreatScore)

Failed Logins:
$($ThreatReport.FailedLogins)

Lockouts:
$($ThreatReport.Lockouts)

Password Sprays:
$($ThreatReport.PasswordSprays)

Brute Force:
$($ThreatReport.BruteForceEvents)

Kerberoasting:
$($ThreatReport.Kerberoasting)

Kerberos Abuse:
$($ThreatReport.KerberosAbuse)

NTLM Abuse:
$($ThreatReport.NTLMAbuse)

Domain Admin Changes:
$($ThreatReport.DomainAdminChanges)

Timestamp:
$(Get-Date)
"@

    Send-EmailAlert `
        -Subject $Subject `
        -Body $Body

    Update-AlertTime `
        -State $State
}

Export-ModuleMember -Function *