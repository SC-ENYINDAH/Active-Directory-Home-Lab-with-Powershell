Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------------------------
# Root
# ---------------------------------

$Root =
Split-Path `
-Parent `
$MyInvocation.MyCommand.Path

# ---------------------------------
# Config
# ---------------------------------

$Global:Config =
Get-Content `
"$Root\Config\settings.json" `
-Raw |
ConvertFrom-Json

$Global:LogPath =
Join-Path `
$Root `
$Global:Config.LogPath

$Global:StateFile =
Join-Path `
$Root `
$Global:Config.StateFile

# ---------------------------------
# Modules
# ---------------------------------

Import-Module `
"$Root\Modules\Logging.psm1" `
-Force

Import-Module `
"$Root\Modules\StateManager.psm1" `
-Force

Import-Module `
"$Root\Modules\EventParser.psm1" `
-Force

Import-Module `
"$Root\Modules\Monitoring.psm1" `
-Force

Import-Module `
"$Root\Modules\ThreatDetection.psm1" `
-Force

Import-Module `
"$Root\Modules\Notifications.psm1" `
-Force

Import-Module `
"$Root\Modules\Audit.psm1" `
-Force

Import-Module ActiveDirectory

# ---------------------------------
# Init
# ---------------------------------

Initialize-Log `
$Global:LogPath

Initialize-State `
$Global:StateFile

# ---------------------------------
# Monitoring Engine
# ---------------------------------

function Start-ADMonitoring {

    while($true)
    {
        try {

            $State =
                Get-State `
                $Global:StateFile

            $Events =
                Get-NewSecurityEvents `
                    -State $State

            if($Events.Count -gt 0)
            {
                Save-State `
                    -State $State `
                    -Path $Global:StateFile

                $ThreatReport =
                    Invoke-ThreatAnalysis `
                        -Events $Events

                Write-Log `
                    -Level "INFO" `
                    -Message "Threat Analysis" `
                    -Data $ThreatReport

                if(
                    $ThreatReport.Severity `
                    -in @(
                        "HIGH",
                        "CRITICAL"
                    )
                )
                {
                    Send-SecurityAlert `
                        -ThreatReport `
                        $ThreatReport `
                        -State `
                        $State
                }

                Clear-Host

                Write-Host ""
                Write-Host "==== ACTIVE DIRECTORY THREAT DASHBOARD ===="
                Write-Host ""

                $ThreatReport |
                Format-List
            }

            Start-Sleep `
                -Seconds `
                $Global:Config.Monitoring.PollingInterval
        }
        catch {

            Write-Log `
                -Level "ERROR" `
                -Message $_.Exception.Message

            Start-Sleep -Seconds 30
        }
    }
}

# ---------------------------------
# Menu
# ---------------------------------

while($true)
{
    Clear-Host

    Write-Host ""
    Write-Host "=========================================="
    Write-Host " Active Directory Detection Console"
    Write-Host "=========================================="
    Write-Host ""

    Write-Host "1. Start Monitoring"
    Write-Host "2. Run Security Audit"
    Write-Host "3. Export Audit Report"
    Write-Host "4. View State"
    Write-Host "Q. Quit"

    Write-Host ""

    $Choice =
        Read-Host "Select"

    switch(
        $Choice.ToUpper()
    )
    {
        "1" {

            Start-ADMonitoring
        }

        "2" {

            Invoke-SecurityAudit |
            ConvertTo-Json -Depth 30
        }

        "3" {

            $Report =
                Export-AuditReport

            Write-Host ""
            Write-Host "Report Saved:"
            Write-Host $Report

            Read-Host
        }

        "4" {

            Get-State `
                $Global:StateFile |
            ConvertTo-Json -Depth 50

            Read-Host
        }

        "Q" {

            break
        }
    }
}