Set-StrictMode -Version Latest

function Get-DomainControllers {

    try {

        Get-ADDomainController `
            -Filter * |
            Select-Object -ExpandProperty HostName
    }
    catch {

        Write-Log `
            -Level "ERROR" `
            -Message "Unable to enumerate Domain Controllers"

        return @()
    }
}

function Initialize-DCState {

    param(
        [object]$State,
        [string]$DC,
        [int]$EventID
    )

    if(-not $State.Events)
    {
        $State | Add-Member `
            -MemberType NoteProperty `
            -Name Events `
            -Value @{}
    }

    if(-not $State.Events.$DC)
    {
        $State.Events |
        Add-Member `
            -MemberType NoteProperty `
            -Name $DC `
            -Value @{}
    }

    if(-not $State.Events.$DC.$EventID)
    {
        $State.Events.$DC |
        Add-Member `
            -MemberType NoteProperty `
            -Name $EventID `
            -Value 0
    }
}

function Get-LastRecordID {

    param(
        [object]$State,
        [string]$DC,
        [int]$EventID
    )

    Initialize-DCState `
        -State $State `
        -DC $DC `
        -EventID $EventID

    return [long]$State.Events.$DC.$EventID
}

function Update-RecordID {

    param(

        [object]$State,

        [string]$DC,

        [int]$EventID,

        [long]$RecordID
    )

    Initialize-DCState `
        -State $State `
        -DC $DC `
        -EventID $EventID

    $State.Events.$DC.$EventID =
        $RecordID
}

function Get-NewEvents {

    param(

        [string]$DomainController,

        [int]$EventID,

        [object]$State
    )

    try {

        $LastRecordID =
            Get-LastRecordID `
                -State $State `
                -DC $DomainController `
                -EventID $EventID

        $Events =
            Get-WinEvent `
                -ComputerName $DomainController `
                -FilterHashtable @{

                    LogName = "Security"
                    ID      = $EventID
                } `
                -ErrorAction Stop

        $NewEvents =
            $Events |
            Where-Object {

                $_.RecordId -gt
                $LastRecordID
            }

        if($NewEvents.Count -gt 0)
        {
            $HighestRecordID =
                (
                    $NewEvents |
                    Measure-Object `
                        RecordId `
                        -Maximum
                ).Maximum

            Update-RecordID `
                -State $State `
                -DC $DomainController `
                -EventID $EventID `
                -RecordID $HighestRecordID
        }

        return $NewEvents
    }
    catch {

        Write-Log `
            -Level "ERROR" `
            -Message (
                "Failed collecting EventID " +
                "$EventID from " +
                "$DomainController : " +
                $_.Exception.Message
            )

        return @()
    }
}

function Get-NewSecurityEvents {

    param(
        [object]$State
    )

    $CollectedEvents =
        New-Object System.Collections.ArrayList

    $DCs =
        Get-DomainControllers

    foreach($DC in $DCs)
    {
        foreach(
            $EventID in
            $Global:Config.MonitoredEventIds
        )
        {
            $Events =
                Get-NewEvents `
                    -DomainController $DC `
                    -EventID $EventID `
                    -State $State

            foreach($Event in $Events)
            {
                try {

                    $Parsed =
                        Convert-WinEventToObject `
                            -Event $Event

                    $Parsed |
                        Add-Member `
                        -MemberType NoteProperty `
                        -Name DomainController `
                        -Value $DC

                    [void]$CollectedEvents.Add(
                        $Parsed
                    )
                }
                catch {

                    Write-Log `
                        -Level "ERROR" `
                        -Message (
                            "Event parsing failure: " +
                            $_.Exception.Message
                        )
                }
            }
        }
    }

    return $CollectedEvents
}

Export-ModuleMember -Function *