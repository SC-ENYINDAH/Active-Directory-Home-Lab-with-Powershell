Import-Module (Join-Path $PSScriptRoot "Modules\root_schema_generator.psm1")

param (
        [string]$JSONFile = "$PSScriptRoot\ad_schema.json"
    )

function ADGroup {
    param (
        [Parameter(Mandatory=$true)]
        $groupObject,
        [string]$Path
    )

    #Get the group from the JSON File
    $name = $groupObject.name

    #Check if group already exists
    if (-not (Get-ADGroup -Filter "Name -eq '$name'" -ErrorAction SilentlyContinue)) {

        New-ADGroup -Name $name -GroupScope Global -ErrorAction Stop

        Write-Host "[+] Group $name created successfully in $Path [+]" -ForegroundColor Green
        Write-Log "Group $name created successfully in $Path" "SUCCESS"
    }
    else {
        Write-Host "[!] Group $name already exists, skipping creation." -ForegroundColor Yellow
    }
    

}

Add a user to an AD group
function AddADUser-ToADGroup {
    param(
        [string]$GroupName,
        [string]$UserSam
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



<# On the queue to attend to 
function Initialize-LabGroups {
    param([string]$JSONFile = "$PSScriptRoot\ad_schema.json")

    $schema = Get-Content $JSONFile -Raw | ConvertFrom-Json
    $DomainName = $schema.domain
    $Users      = $schema.users

    foreach ($user in $Users) {
        $name   = $user.name
        $groups = $user.groups

        # Use helper function for SamAccountName
        $samAccountName = Get-SamAccountName -FullName $name

        foreach ($group in $groups) {
            # Use helper function for group path
            $groupPath = Get-GroupPath -DomainName $DomainName

            # Ensure group exists
            New-LabGroup -Name $group -Path $groupPath

            # Add user to group
            Add-LabUserToGroup -GroupName $group -UserSam $samAccountName
        }
    }
}
#>







function CreateGroups_Handle_JSONFile {

    $GetJSONFile = Get-Content $JSONFile -Raw | ConvertFrom-Json
    $global:groupName = $GetJSONFile.groups
    $global:DomainName = $GetJSONFile.domain
    $global:ou = $GetJSONFile.ou
    $global:users = $GetJSONFile.users

    foreach ($group in $GetJSONFile.groups){
        ADGroup $group
    }  

}

CreateGroups_Handle_JSONFile