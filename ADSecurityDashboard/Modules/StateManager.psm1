Set-StrictMode -Version Latest

function Initialize-State {

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
        $InitialState = @{
            LastAlert = ""
            Events    = @{}
        }

        $InitialState |
        ConvertTo-Json -Depth 20 |
        Set-Content $Path
    }
}

function Get-State {

    param(
        [string]$Path
    )

    try {

        if(-not(Test-Path $Path))
        {
            Initialize-State $Path
        }

        return (
            Get-Content `
                $Path `
                -Raw |
            ConvertFrom-Json
        )
    }
    catch {

        throw "Unable to read state file: $Path"
    }
}

function Save-State {

    param(
        [object]$State,
        [string]$Path
    )

    try {

        $State |
        ConvertTo-Json -Depth 50 |
        Set-Content `
            -Path $Path `
            -Encoding UTF8
    }
    catch {

        throw "Unable to save state file."
    }
}

function Initialize-RecordTracking {

    param(

        [object]$State,

        [string]$DomainController,

        [int]$EventID
    )

    if(-not $State.Events.$DomainController)
    {
        $State.Events |
        Add-Member `
            NoteProperty `
            $DomainController `
            @{}
    }

    if(-not $State.Events.$DomainController.$EventID)
    {
        $State.Events.$DomainController |
        Add-Member `
            NoteProperty `
            $EventID `
            0
    }
}

function Get-LastRecordID {

    param(

        [object]$State,

        [string]$DomainController,

        [int]$EventID
    )

    Initialize-RecordTracking `
        -State $State `
        -DomainController $DomainController `
        -EventID $EventID

    return [long]
    $State.Events.$DomainController.$EventID
}

function Set-LastRecordID {

    param(

        [object]$State,

        [string]$DomainController,

        [int]$EventID,

        [long]$RecordID
    )

    Initialize-RecordTracking `
        -State $State `
        -DomainController $DomainController `
        -EventID $EventID

    $State.Events.$DomainController.$EventID =
        $RecordID
}

Export-ModuleMember -Function *