Import-Module (Join-Path $PSScriptRoot "Modules\root_schema_generator.psm1")
Import-Module (Join-Path $PSScriptRoot "Modules\password_security_policy.psm1")
Import-Module (Join-Path $PSScriptRoot "Modules\Hold_Envariables.psm1")

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

    # Check complexity rules and enhance if needed
    if ($policy.ComplexityEnabled) {
        $complexityFailed = (
            $Password -notmatch '[A-Z]' -or
            $Password -notmatch '[a-z]' -or
            $Password -notmatch '\d' -or
            $Password -notmatch '[^a-zA-Z0-9]'
        )

        if ($complexityFailed) {
            Write-Verbose "Password does not meet complexity requirements. Enhancing password."
            
        }
    }

    # Prevent username to be use as password
    if ($Password -like "*$UserName*") {
        throw "Password cannot contain your username."
    }
    return $Password
}

function CreateADUser {
    param (
        [Parameter(Mandatory=$true)]
        $UserObject,
        [string]$Passwd
    )

    try {
        
        #Get names, passwords and ou's from the JSON File
        $name = $UserObject.name
        $password = $UserObject.password
        $ou = $UserObject.ou

        #Create the first and last initials for the username
        $samAccountName = Get-SamAccountName -Fullname $name
        $userPrincipalName = Get-UserPrincipalName -samAccountName $samAccountName -DomainName $global:DomainName
        $username = Get-SamAccountName -UserName $name

        <#
        $firstname, $lastname = $name.split(" ")
        $username = ($firstname[0] + $lastname).ToLower()
        $samAccountName = $username
        $principalName = $username
        #>

        #Verify that the @Global:DomainName is populated before creating the users
        if (-not $global:DomainName) {
            throw "Domain is not defined in JSON file."

        }

        # Validate password against policy 

        if (-not (Test-PasswordPolicy -Password $password -UserName $username)) {
            Write-Verbose "==========Enhancing password=========="
            $Password = EnhacePassword -Passwd $Password
        }

        $firstname, $lastname = $name.split(" ")

        #Creating the ADUser Object
        New-ADUser -Name $name -GivenName $firstname -Surname $lastname `
        -SamAccountName $samAccountName -UserPrincipalName $userPrincipalName `
        -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -Path $ou -PassThru | Enable-ADAccount


        Write-Host "[+] ....User $name created successfully in $ou ...... [+]" -ForegroundColor Green
        Write-Log "[+] ...User $name created successfully with UPN $userPrincipalName... [+]" "SUCCESS"

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