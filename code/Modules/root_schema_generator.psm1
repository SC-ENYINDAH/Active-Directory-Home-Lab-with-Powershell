param(
    [string]$JSONFile
)

$script:firstname = [System.Collections.ArrayList](Get-Content "$PSScriptRoot\..\data\first_names.txt")
$script:lastname = [System.Collections.ArrayList](Get-Content "$PSScriptRoot\..\data\last_names.txt")
$script:password = [System.Collections.ArrayList](Get-Content "$PSScriptRoot\..\data\passwords.txt")
$script:groups = [System.Collections.ArrayList](Get-Content "$PSScriptRoot\..\data\group_names.txt")

$script:group = @()
$script:users = @()

$grp_num = 10
$users_num = 100

$baseDir = if ($PSScriptRoot) { $PSScriptRoot } else { Get-Location }

if (-not $JSONFile) {
    $JSONFile = Get-ChildItem -Path $baseDir -Filter "ad_schema.json" -Recurse -File
}

function CreateGroup {
    
    for ($i=0; $i -lt $grp_num; $i++){

        $hold_grp = (Get-Random -InputObject $script:groups)
        $script:group += @{"name" = "$hold_grp"}

        $script:groups.Remove($hold_grp) | Out-Null
    }

    if ($script:group.Count -eq 0){

        return ,@()

    }

     return, $script:group
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


        $fname =  $script:firstname |Get-Random
        $lname =  $script:lastname | Get-Random
        $passwd = $script:password | Get-Random
        $get_random = $grps | Get-Random

        #Generating Hashtables for new users
        $new_users = ( [ordered] @{

            "name" = "$fname $lname"
            "password" = "$passwd"
            "groups" = @(($get_random).name)
            "SafeModeAdministratorPassword" = "$SafeModePassword"
            "path" = "OU=$(($get_random).name), $DN"
            
        } )
    $script:users += $new_users

    $script:firstname.Remove($fname) | Out-Null
    $script:lastname.Remove($lname) | Out-Null
    $script:password.Remove($passwd) | Out-Null
    }

}

function Domain {

    param( [string]$inputDomain)

     $domain = ([ordered] @{
        
        "domain" = "$inputDomain"
        "users" = $script:users
        "groups" = $script:group
        
        
    } )
    ConvertTo-Json -InputObject $domain -Depth 5| Out-File -FilePath $JSONFile
}

function GetInput {
   
    Write-Host "Enter Your Preferred Domain Name:" -ForegroundColor Yellow
    $GetDomain = Read-Host
    Write-Host "You entered: $GetDomain" -ForegroundColor Green

    #split the daomain into Domain Name Format
    $DomainSplit = $GetDomain.split(".")
    $script:DN = ($DomainSplit | ForEach-Object {"DC=$_"}) -join ","


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

    $script:SafeModePassword = $pwd1
    $SafeModePassword
    Write-Host "[+] SafeModeAdministratorPassword confirmed." -ForegroundColor Green


    Write-Host "Do you wish to continue? (Y(es), blank=(cancel))" -ForegroundColor Red
    $GetResponse = Read-Host

    if ($GetResponse -eq 'Y') {
        Write-Host "[+] Continuing with domain setup..." -ForegroundColor Green

        $UserGroup = CreateGroup 

        GetUsers -grps $UserGroup
    
        Domain -inputDomain $GetDomain
        $script:users
    
    }

    else {

        Write-Host "[-] Operation cancelled." -ForegroundColor Red
        exit
    }

}


Export-ModuleMember -Function GetInput, EnhacePassword