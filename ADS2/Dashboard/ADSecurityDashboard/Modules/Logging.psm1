Set-StrictMode -Version Latest

function Initialize-Log {

    param(
        [string]$Path
    )

    $Folder = Split-Path $Path

    if(-not(Test-Path $Folder))
    {
        New-Item `
            -ItemType Directory `
            -Path $Folder `
            -Force | Out-Null
    }

    if(-not(Test-Path $Path))
    {
        New-Item `
            -ItemType File `
            -Path $Path `
            -Force | Out-Null
    }
}

function Rotate-Log {

    $MaxSizeMB =
        $Global:Config.Logging.MaxLogSizeMB

    if(-not(Test-Path $Global:LogPath))
    {
        return
    }

    $CurrentSize =
        (
            Get-Item $Global:LogPath
        ).Length / 1MB

    if($CurrentSize -lt $MaxSizeMB)
    {
        return
    }

    $Timestamp =
        Get-Date -Format yyyyMMddHHmmss

    $Archive =
        "$($Global:LogPath).$Timestamp"

    Move-Item `
        -Path $Global:LogPath `
        -Destination $Archive `
        -Force

    New-Item `
        -Path $Global:LogPath `
        -ItemType File `
        -Force | Out-Null

    Remove-OldLogs
}

function Remove-OldLogs {

    $RetentionDays =
        $Global:Config.Logging.RetentionDays

    Get-ChildItem `
        (Split-Path $Global:LogPath) `
        -File |

        Where-Object {

            $_.LastWriteTime -lt
            (Get-Date).AddDays(
                -$RetentionDays
            )
        } |

        Remove-Item -Force
}

function Write-Log {

    param(

        [string]$Level,

        [string]$Message,

        [object]$Data
    )

    Rotate-Log

    $Entry = [PSCustomObject]@{

        Timestamp =
            (Get-Date).ToString("o")

        Level =
            $Level

        Message =
            $Message

        Data =
            $Data
    }

    $Entry |
    ConvertTo-Json -Depth 20 -Compress |
    Add-Content `
        -Path $Global:LogPath `
        -Encoding UTF8
}

Export-ModuleMember -Function *