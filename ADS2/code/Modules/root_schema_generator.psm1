param(

    [string]$JSONFile = (Join-Path $PSScriptRoot ".\ad_schema.json")
)

$global:firstname = [System.Collections.ArrayList](Get-Content "$PSScriptRoot\data\first_names.txt")
$global:lastname = [System.Collections.ArrayList](Get-Content "$PSScriptRoot\data\last_names.txt")
$global:password = [System.Collections.ArrayList](Get-Content "$PSScriptRoot\data\passwords.txt")
$global:groups = [System.Collections.ArrayList](Get-Content "$PSScriptRoot\data\group_names.txt")

$global:group = @()
$global:users = @()

$grp_num = 10
$users_num = 100

function CreateGroup {
    
    for ($i=0; $i -lt $grp_num; $i++){

        $hold_grp = (Get-Random -InputObject $global:groups)
        $global:group += @{"name" = "$hold_grp"}

        $groups.Remove($hold_grp) | Out-Null
    }

    if ($global:group.Count -eq 0){

        return ,@()

    }

     return, $global:group
}

function EnhacePassword {
    param (
        [int]$Length = 2
    )

    # Character sets
    $upper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray()
    $lower   = "abcdefghijklmnopqrstuvwxyz".ToCharArray()
    $digits  = "0123456789".ToCharArray()
    $special = "!@#$%^&*()-_=+[]{};:,.<>?/".ToCharArray()

    # Ensure at least one of each type
    $result = @()
    $result += $upper  | Get-Random -Count (Get-Random -Minimum 1 -Maximum 4)
    $result += $lower  | Get-Random -Count (Get-Random -Minimum 1 -Maximum 4)
    $result += $digits | Get-Random -Count (Get-Random -Minimum 1 -Maximum 4)
    $result += $special| Get-Random -Count (Get-Random -Minimum 1 -Maximum 4)

    # Fill the rest randomly from all sets combined
    $allChars = ($upper + $lower + $digits + $special)
    $remaining = $Length - $result.Count
    if ($remaining -gt 0) {
        $result += $allChars | Get-Random -Count $remaining
    }

    # Shuffle and return as string
    -join ($result | Sort-Object {Get-Random})
}

function GetUsers{

    param($grps)

    for ($i = 0; $i -lt $users_num; $i++) {


        $fname =  $global:firstname |Get-Random
        $lname =  $global:lastname | Get-Random
        $passwd = $global:password | Get-Random
        $get_random = $grps | Get-Random

        #Generating Hashtables for new users
        $new_users = ( [ordered] @{

            "name" = "$fname $lname"
            "password" = "$passwd"
            "groups" = @(($get_random).name)
            "SafeModeAdministratorPassword" = "$SafeModePassword"
            "path" = "OU=$(($get_random).name), $DN"
            
        } )
    $global:users += $new_users

    $global:firstname.Remove($fname) | Out-Null
    $global:lastname.Remove($lname) | Out-Null
    $global:password.Remove($passwd) | Out-Null
    }

}

function Domain {

    param( [string]$inputDomain)

     $domain = ([ordered] @{
        
        "domain" = "$inputDomain"
        "users" = $global:users
        "groups" = $global:group
        
        
    } ) #Out-File -FilePath $JSONFile
    ConvertTo-Json -InputObject $domain -Depth 5| Out-File -FilePath $JSONFile
}

function GetInput {
   
    Write-Host "Enter Your Preferred Domain Name:" -ForegroundColor Yellow
    $GetDomain = Read-Host
    Write-Host "You entered: $GetDomain" -ForegroundColor Green

    #split the daomain into Domain Name Format
    $DomainSplit = $GetDomain.split(".")
    $global:DN = ($DomainSplit | ForEach-Object {"DC=$_"}) -join ","


    do {

        Write-Host "Enter SafeModeAdministratorPassword" 
        $pwd1 = Read-Host -AsSecureString
        Write-Host "Confirm SafeModeAdministratorPassword" 
        $pwd2 = Read-Host -AsSecureString

        # Convert back to plain text for comparison
        $pass1 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($pwd1))
        $pass2 = [Runtime.InteropServices.Marshal]::PtrToStringAuto( [Runtime.InteropServices.Marshal]::SecureStringToBSTR($pwd2))

        if ($pass1 -ne $pass2) {
            Write-Host "[+] Passwords do not match. Please try again." -ForegroundColor Red
        }
    } 
    until ($pass1 -eq $pass2)

    $global:SafeModePassword = $pwd1
    $SafeModePassword
    Write-Host "[+] SafeModeAdministratorPassword confirmed." -ForegroundColor Green


    Write-Host "Do you wish to continue? (Y(es), blank=(cancel))" -ForegroundColor Red
    $GetResponse = Read-Host

    if ($GetResponse -eq 'Y') {
        Write-Host "[+] Continuing with domain setup..." -ForegroundColor Green

        $UserGroup = CreateGroup 

        GetUsers -grps $UserGroup
    
        Domain -inputDomain $GetDomain
        $global:users
    
    }

    else {

        Write-Host "[-] Operation cancelled." -ForegroundColor Red
        exit
    }

}


Export-ModuleMember -Function GetInput, EnhacePassword