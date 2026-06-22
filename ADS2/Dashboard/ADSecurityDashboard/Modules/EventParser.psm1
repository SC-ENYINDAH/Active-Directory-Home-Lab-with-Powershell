Set-StrictMode -Version Latest

function Convert-WinEventToObject {

    param(
        [System.Diagnostics.Eventing.Reader.EventRecord]$Event
    )

    try {

        $XML =
            [xml]$Event.ToXml()

        $EventData = @{}

        foreach(
            $Field in
            $XML.Event.EventData.Data
        )
        {
            $EventData[
                $Field.Name
            ] =
            $Field.'#text'
        }

        [PSCustomObject]@{

            EventID =
                $Event.Id

            RecordID =
                $Event.RecordId

            TimeCreated =
                $Event.TimeCreated

            MachineName =
                $Event.MachineName

            EventData =
                [PSCustomObject]$EventData

            RawMessage =
                $Event.FormatDescription()
        }
    }
    catch {

        Write-Log `
            -Level "ERROR" `
            -Message (
                "Event Parse Error: " +
                $_.Exception.Message
            )

        return $null
    }
}

function Convert-Events {

    param(
        [array]$Events
    )

    $Results =
        New-Object System.Collections.ArrayList

    foreach($Event in $Events)
    {
        $Parsed =
            Convert-WinEventToObject $Event

        if($Parsed)
        {
            [void]
            $Results.Add($Parsed)
        }
    }

    return $Results
}

Export-ModuleMember -Function *