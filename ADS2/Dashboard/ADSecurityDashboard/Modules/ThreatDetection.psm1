Set-StrictMode -Version Latest

# ----------------------------------------------------
# Brute Force Detection
# One User - Many Failures
# ----------------------------------------------------

function Detect-BruteForce {

    param(
        [array]$Events
    )

    $Threshold =
        $Global:Config.Thresholds.BruteforceAttempts

    $Events |
    Where-Object {
        $_.EventId -eq 4625
    } |
    Group-Object {
        $_.EventData.TargetUserName
    } |
    Where-Object {
        $_.Count -ge $Threshold
    }
}

# ----------------------------------------------------
# Password Spray
# One IP - Many Users
# ----------------------------------------------------

function Detect-PasswordSpray {

    param(
        [array]$Events
    )

    $Threshold =
        $Global:Config.Thresholds.PasswordSprayUsers

    $Events |
    Where-Object {
        $_.EventId -eq 4625
    } |
    Group-Object {
        $_.EventData.IpAddress
    } |
    Where-Object {

        (
            $_.Group.EventData.TargetUserName |
            Select-Object -Unique
        ).Count -ge $Threshold
    }
}

# ----------------------------------------------------
# Account Lockouts
# Event ID 4740
# ----------------------------------------------------

function Detect-Lockouts {

    param(
        [array]$Events
    )

    $Events |
    Where-Object {
        $_.EventId -eq 4740
    }
}

# ----------------------------------------------------
# Privileged Logons
# Event ID 4672
# ----------------------------------------------------

function Detect-PrivilegedLogons {

    param(
        [array]$Events
    )

    $Events |
    Where-Object {
        $_.EventId -eq 4672
    }
}

# ----------------------------------------------------
# Domain Admin Changes
# Event ID 4728
# ----------------------------------------------------

function Detect-DomainAdminChanges {

    param(
        [array]$Events
    )

    $Events |
    Where-Object {
        $_.EventId -eq 4728
    }
}

# ----------------------------------------------------
# Kerberos TGT Abuse
# Event ID 4768
# ----------------------------------------------------

function Detect-KerberosAbuse {

    param(
        [array]$Events
    )

    $Events |
    Where-Object {
        $_.EventId -eq 4768
    } |
    Group-Object {
        $_.EventData.TargetUserName
    } |
    Where-Object {
        $_.Count -gt 25
    }
}

# ----------------------------------------------------
# Kerberoasting
# Event ID 4769
# ----------------------------------------------------

function Detect-Kerberoasting {

    param(
        [array]$Events
    )

    $Events |
    Where-Object {
        $_.EventId -eq 4769
    } |
    Group-Object {
        $_.EventData.TargetUserName
    } |
    Where-Object {
        $_.Count -gt 20
    }
}

# ----------------------------------------------------
# NTLM Abuse
# Event ID 4776
# ----------------------------------------------------

function Detect-NTLMAbuse {

    param(
        [array]$Events
    )

    $Events |
    Where-Object {
        $_.EventId -eq 4776
    } |
    Group-Object {
        $_.EventData.Workstation
    } |
    Where-Object {
        $_.Count -gt 20
    }
}

# ----------------------------------------------------
# Privileged Account Targeting
# ----------------------------------------------------

function Detect-PrivilegedAccountTargeting {

    param(
        [array]$Events
    )

    $Events |
    Where-Object {

        $_.EventData.TargetUserName -in
        $Global:Config.PrivilegedAccounts
    }
}

# ----------------------------------------------------
# IOC Generation
# ----------------------------------------------------

function Get-IndicatorsOfCompromise {

    param(
        [array]$Events
    )

    $IOC =
        New-Object System.Collections.ArrayList

    foreach($Event in $Events)
    {
        try {

            [void]$IOC.Add(

                [PSCustomObject]@{

                    Timestamp =
                        $Event.TimeCreated

                    EventID =
                        $Event.EventId

                    User =
                        $Event.EventData.TargetUserName

                    SourceIP =
                        $Event.EventData.IpAddress

                    Host =
                        $Event.DomainController
                }
            )
        }
        catch {}
    }

    return $IOC
}

# ----------------------------------------------------
# Threat Scoring
# ----------------------------------------------------

function Get-ThreatScore {

    param(

        [int]$FailedLogins,

        [int]$Lockouts,

        [bool]$PasswordSpray,

        [bool]$BruteForce,

        [bool]$KerberosAbuse,

        [bool]$Kerberoasting,

        [bool]$PrivilegedLogon,

        [bool]$DomainAdminChange,

        [bool]$NTLMAbuse,

        [bool]$PrivilegedAccountAttack
    )

    $Score = 0

    if($FailedLogins -gt 10)
    {
        $Score += 20
    }

    if($Lockouts -gt 5)
    {
        $Score += 30
    }

    if($PasswordSpray)
    {
        $Score += 50
    }

    if($BruteForce)
    {
        $Score += 40
    }

    if($KerberosAbuse)
    {
        $Score += 40
    }

    if($Kerberoasting)
    {
        $Score += 60
    }

    if($PrivilegedLogon)
    {
        $Score += 40
    }

    if($DomainAdminChange)
    {
        $Score += 80
    }

    if($NTLMAbuse)
    {
        $Score += 30
    }

    if($PrivilegedAccountAttack)
    {
        $Score += 70
    }

    return $Score
}

# ----------------------------------------------------
# Severity Mapping
# ----------------------------------------------------

function Get-Severity {

    param(
        [int]$Score
    )

    switch($Score)
    {
        {$_ -lt 20}
        {
            "LOW"
        }

        {$_ -lt 50}
        {
            "MEDIUM"
        }

        {$_ -lt 80}
        {
            "HIGH"
        }

        default
        {
            "CRITICAL"
        }
    }
}

# ----------------------------------------------------
# Unified Analysis Engine
# ----------------------------------------------------

function Invoke-ThreatAnalysis {

    param(
        [array]$Events
    )

    $FailedLogins =
        $Events |
        Where-Object {
            $_.EventId -eq 4625
        }

    $BruteForce =
        Detect-BruteForce $Events

    $PasswordSpray =
        Detect-PasswordSpray $Events

    $Lockouts =
        Detect-Lockouts $Events

    $KerberosAbuse =
        Detect-KerberosAbuse $Events

    $Kerberoasting =
        Detect-Kerberoasting $Events

    $PrivilegedLogons =
        Detect-PrivilegedLogons $Events

    $DomainAdminChanges =
        Detect-DomainAdminChanges $Events

    $NTLMAbuse =
        Detect-NTLMAbuse $Events

    $PrivilegedAttack =
        Detect-PrivilegedAccountTargeting $Events

    $Score =
        Get-ThreatScore `
            -FailedLogins $FailedLogins.Count `
            -Lockouts $Lockouts.Count `
            -PasswordSpray ($PasswordSpray.Count -gt 0) `
            -BruteForce ($BruteForce.Count -gt 0) `
            -KerberosAbuse ($KerberosAbuse.Count -gt 0) `
            -Kerberoasting ($Kerberoasting.Count -gt 0) `
            -PrivilegedLogon ($PrivilegedLogons.Count -gt 0) `
            -DomainAdminChange ($DomainAdminChanges.Count -gt 0) `
            -NTLMAbuse ($NTLMAbuse.Count -gt 0) `
            -PrivilegedAccountAttack ($PrivilegedAttack.Count -gt 0)

    $Severity =
        Get-Severity $Score

    [PSCustomObject]@{

        Timestamp =
            Get-Date

        Severity =
            $Severity

        ThreatScore =
            $Score

        FailedLogins =
            $FailedLogins.Count

        Lockouts =
            $Lockouts.Count

        BruteForceEvents =
            $BruteForce.Count

        PasswordSprays =
            $PasswordSpray.Count

        KerberosAbuse =
            $KerberosAbuse.Count

        Kerberoasting =
            $Kerberoasting.Count

        NTLMAbuse =
            $NTLMAbuse.Count

        PrivilegedLogons =
            $PrivilegedLogons.Count

        DomainAdminChanges =
            $DomainAdminChanges.Count

        PrivilegedAccountAttacks =
            $PrivilegedAttack.Count

        IOC =
            Get-IndicatorsOfCompromise $Events
    }
}

Export-ModuleMember -Function *