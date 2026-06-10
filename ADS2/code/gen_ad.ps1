param (
    #[Parameter(Mandatory=$true)] #//Mandatory=$true prompt for input whenever the script is executed
    
    [string]$JSONFile = (Join-Path $PSScriptRoot "ad_schema.json")
)

#Creating the Groups in the ADGroup Object
function ADGroup {
    param (
        [Parameter(Mandatory=$true)]
        $groupObject
    )

    #Get the group from the JSON File
    $name = $groupObject.name


    #Check if group already exists
    if (-not (Get-ADGroup -Filter "Name -eq '$name'" -ErrorAction SilentlyContinue)) {

        New-ADGroup -Name $name -GroupScope Global -ErrorAction Stop
    }

}

#Creating Users Object 
function CreateADUser {
    param (
        [Parameter(Mandatory=$true)]
        $UserObject
    )
    
    #Get the name from the JSON File
    $name = $UserObject.name
    $password = $UserObject.password

    #Create the first and last initials for the username
    $firstname, $lastname = $name.split(" ")
    $username = ($firstname[0] + $lastname).ToLower()
    $samAccountName = $username
    $principalName = $username


    #Verify that the @Global:Domain is populated before creating the users
    if (-not $Global:Domain) {
        throw "Domain is not defined in JSON file."

    }

    #Creating the ADUser Object
    $userPrincipalName = "$principalName@$Global:Domain"
    New-ADUser -Name $name -GivenName $firstname -Surname $lastname `
    -SamAccountName $samAccountName -UserPrincipalName $userPrincipalName `
    -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -PassThru | Enable-ADAccount 
   
    foreach ($group in $UserObject.groups){

        try {
            Get-ADGroup -Identity "$group" 
            Add-ADGroupMember -Identity $group -Members $username
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]{
            Write-Warning "Group $group not found while adding user $name"

        }
    }

}

<#function RemoveADgROUP{

    param(
        [Parameter(Mandatory=$true)]$groupObject
    )

    $name = $groupObject.name

    Remove-ADGroup -Identity $name -Confirm:$false

}

function RemoveADUser{

    param(
        [Parameter(Mandatory=$true)]$UserObject
    )

    $name = $UserObject.name
    $firstname, $lastname = $name.split(" ")
    $username = ($firstname[0] + $lastname).ToLower()
    $samAccountName = $username

    Remove-ADUser -Identity $samAccountName -Confirm:$false
} #>

function passwordPolicy {

secedit /export /cfg c:\secpol.cfg
(Get-Content C:\secpol.cfg).replace("PasswordComplexity = 1", "PasswordComplexity = 0").replace("MinimumPasswordLength = 7", "MinimumPasswordLength = 1") | Out-File C:\secpol.cfg
secedit /configure /db c:\windows\security\local.sdb /cfg c:\windows\Tasks\secpol.cfg /areas SECURITYPOLICY
Remove-Item -force c:\secpol.cfg -confirm:$false

}

#$JSONFile

function Handle_JSONFile {

    $json = (Get-Content $JSONFile | ConvertFrom-Json)
    $Global:Domain = $json.domain
   # $Global:Domain = (Get-ADDomain).DNSRoot  // This queries Active Directory for information about the domain and the property of the domain object

    foreach ($group in $json.groups){
        ADGroup $group
    }

    foreach ($user in $json.users){
        CreateADUser $user
    }
     #Write-Output $json.users

}

passwordPolicy
Handle_JSONFile

