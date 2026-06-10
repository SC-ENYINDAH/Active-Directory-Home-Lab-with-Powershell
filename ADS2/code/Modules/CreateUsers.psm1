Import-Module (Join-Path $PSScriptRoot "Modules\root_schema_generator.psm1")
Import-Module (Join-Path $PSScriptRoot "Modules\password_security_policy.psm1")

param (
        [string]$JSONFile = "$PSScriptRoot\ad_schema.json"
    )

#Enforce AD Domain Policy
Set-AccountLockoutPolicy 
Set-PasswordSecPolicy

GetInput 

function Test-PasswordPolicy {
    param([string]$Password, [string]$UserName)

    $global:policy = Get-ADDefaultDomainPasswordPolicy

    # Check minimum length
    if ($Password.Length -lt $policy.MinPasswordLength) {
        throw "Password must be at least $($policy.MinPasswordLength) characters long."
    }

    # Check complexity rules
    if ($policy.ComplexityEnabled) {
        #$PassEnhancer = $false

        if ($Password -notmatch '[A-Z]') { throw "Password does not meet complexity requirement" }
        if ($Password -notmatch '[a-z]') { throw "Password does not meet complexity requirement" }
        if ($Password -notmatch '\d')    { throw "Password does not meet complexity requirement" }
        if ($Password -notmatch '[^a-zA-Z0-9]') { throw "Password does not meet complexity requirement" }
    }

    # Prevent username to be use as password
    if ($Password -like "*$UserName*") {
        throw "Password cannot contain your username."
    }
    return $true
}

function CreateADUser {
    param (
        [Parameter(Mandatory=$true)]$UserObject
    )

    try {
        
        #Get names, passwords and ou's from the JSON File
        $name = $UserObject.name
        $password = $UserObject.password
        $ou = $UserObject.ou
        $groups= $UserObject.groups

        #Create the first and last initials for the username
        $firstname, $lastname = $name.split(" ")
        $username = ($firstname[0] + $lastname).ToLower()
        $samAccountName = $username
        $principalName = $username


        #Verify that the @Global:DomainName is populated before creating the users
        if (-not $global:DomainName) {
            throw "Domain is not defined in JSON file."

        }

        # Validate password against policy
        $password = Test-PasswordPolicy -Password $password -UserName $username

        #Creating the ADUser Object
        $userPrincipalName = "$principalName@$global:DomainName"
        New-ADUser -Name $name -GivenName $firstname -Surname $lastname `
        -SamAccountName $samAccountName -UserPrincipalName $userPrincipalName `
        -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -Path $ou -PassThru | Enable-ADAccount


        Write-Host "[+] ....User $name created successfully in $ou ...... [+]" -ForegroundColor Green
        Write-Log "[+] ...User $name created successfully with UPN $userPrincipalName... [+]" "SUCCESS"


        #Work on from create group
        <#foreach ($group in $groups) {
            $groupPath = "OU=Groups,DC=$($DomainName.Split('.')[0]),DC=$($DomainName.Split('.')[1]),DC=$($DomainName.Split('.')[2]),DC=$($DomainName.Split('.')[3])"
            New-LabGroup -Name $group -Path $groupPath
            Add-LabUserToGroup -GroupName $group -UserSam $samAccountName
        }#>

    }
    catch {

        Write-Host "[-] Failed to create user $name : $_" -ForegroundColor Red
        Write-Log "[-] Failed to create user $name. Error: $_" "ERROR"
    }  

}

function CreateUser_Handle_JSONFile {

    $GetJSONFile = Get-Content $JSONFile -Raw | ConvertFrom-Json
    $global:DomainName = $GetJSONFile.domain
   # $Global:Domain = (Get-ADDomain).DNSRoot  // This queries Active Directory for information about the domain and the property of the domain object

    foreach ($user in $GetJSONFile.users){
        CreateADUser $user
    }  

}

Export-ModuleMember -Function CreateUser_Handle_JSONFile