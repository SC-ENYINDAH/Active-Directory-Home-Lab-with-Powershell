param(

    [string]$JSONFile = (Join-Path $PSScriptRoot ".\still.json"),
    [switch]$undo
)

$firstname = [System.Collections.ArrayList](Get-Content "$PSScriptRoot\data\first_names.txt")
$lastname = [System.Collections.ArrayList](Get-Content "$PSScriptRoot\data\last_names.txt")
$password = [System.Collections.ArrayList](Get-Content "$PSScriptRoot\data\passwords.txt")
$groups = [System.Collections.ArrayList](Get-Content "$PSScriptRoot\data\group_names.txt")

$group = @()
$users = @()

$grp_num = 10
$users_num = 100

for ($i=0; $i -lt $grp_num; $i++){

    $hold_grp = (Get-Random -InputObject $groups)
    $group += @{"name" = "$hold_grp"}

    $groups.Remove($hold_grp) | Out-Null

}


for ($i=0; $i -lt $users_num; $i++){

    $fname = (Get-Random -InputObject $firstname)
    $lname = (Get-Random -InputObject $lastname)
    $passwd = (Get-Random -InputObject $password)

    $new_user = @{

        "name" = "$fname $lname"
        "password" = "$passwd"
        "group" = @((Get-Random -InputObject $group).name)
    }
    $users += $new_user

    $firstname.Remove($fname) | Out-Null
    $lastname.Remove($lname) | Out-Null
    $password.Remove($passwd) | Out-Null
}

    $domain = ([ordered] @{
        
        "domain" = "samchi_seclab.local"
        "users" = $users
        "groups" = $group
        
        
    } ) #Out-File -FilePath $JSONFile
    ConvertTo-Json -InputObject $domain -Depth 4| Out-File -FilePath $JSONFile

    $domain
    $users