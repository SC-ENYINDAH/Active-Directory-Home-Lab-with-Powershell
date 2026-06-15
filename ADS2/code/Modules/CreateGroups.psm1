Import-Module (Join-Path $PSScriptRoot "Modules\root_schema_generator.psm1")
Import-Module (Join-Path $PSScriptRoot "Modules\Hold_Envariables.psm1")
param (
        [string]$JSONFile = "$PSScriptRoot\ad_schema.json"
    )

function Create-ADGroup {
    param (
        [Parameter(Mandatory=$true)]$groupObject,
        [string]$DomainName = $global:DomainName,
        [string]$ou
    )

    #Get the group names and paths from the JSON File
    $name = $groupObject.name
    $path = $groupObject.path

    #check if path exists, if not create it 
    if (-not $path) {
        $path = Get-GroupPath -DomainName $global:DomainName
    }

    try {
        #Check if group already exists
    if (-not (Get-ADGroup -Filter "Name -eq '$name'" -ErrorAction SilentlyContinue)) {

        New-ADGroup -Name $name -GroupScope Global -Path $path -ErrorAction Stop

        Write-Host "[+] Group $name created successfully in $path [+]" -ForegroundColor Green
        Write-Log "Group $name created successfully in $path" "SUCCESS"
    }
    else {
        Write-Host "[!] Group $name already exists, skipping creation." -ForegroundColor Yellow
    }
    }
    catch {
        Write-Host "[-] Failed to create group $name : $_ [-]" -ForegroundColor Red
        Write-Log "Failed to create group $name. Error: $_" "ERROR"
    }

}
function Add-UserToADGroup {
    param(
        $GroupName,
        $UserSam
    )

    try {
        Add-ADGroupMember -Identity $GroupName -Members $UserSam -ErrorAction Stop
        Write-Host "[+] User $UserSam added to group $GroupName [+]" -ForegroundColor Green
        Write-Log "User $UserSam added to group $GroupName" "SUCCESS"
    }
    catch {
        Write-Host "[-] Failed to add $UserSam to $GroupName : $_ [-]" -ForegroundColor Red
        Write-Log "Failed to add $UserSam to $GroupName. Error: $_" "ERROR"
    }
}

function CreateGroups_Handle_JSONFile {

    $GetJSONFile = Get-Content $JSONFile -Raw | ConvertFrom-Json
    $global:groupName = $GetJSONFile.groups
    $global:DomainName = $GetJSONFile.domain
    $global:users = $GetJSONFile.users

    foreach ($group in $groupName){
        Create-ADGroup -groupObject $group -DomainName $global:DomainName
    }  

    foreach ($user in $global:users){
        $name = $user.name

        foreach ($group in $user.groups) {
            Add-UserToADGroup -GroupName $group -UserSam (Get-SamAccountName -FullName $name)
        }
    }

}

CreateGroups_Handle_JSONFile