param(

    [string]$JSONFile = (Join-Path $PSScriptRoot ".\out.json"),
    [switch]$undo
)

$global:firstname = [System.Collections.ArrayList](Get-Content "$PSScriptRoot\data\first_names.txt")
$global:lastname = [System.Collections.ArrayList](Get-Content "$PSScriptRoot\data\last_names.txt")
$global:password = [System.Collections.ArrayList](Get-Content "$PSScriptRoot\data\passwords.txt")
$global:groups = [System.Collections.ArrayList](Get-Content "$PSScriptRoot\data\group_names.txt")

$global:group = @()
$global:users = @()

$grp_num = 10
$users_num = 100


function Getgroup {
   param($hold_group)

    $groupArray = @()

    $localCp = [System.Collections.ArrayList]$hold_group.Clone()


    for ($i = 0; $i -lt $grp_num; $i++) {
        if ($localCp.Count -eq 0) { break }

        $chosenGroup =  $localCp | Get-Random
        
        # Append the hashtable to the local array
        $groupArray += @{ "name" = "$chosenGroup" }

        # Remove the created group so it doesn't get picked again
        $localCp.Remove($chosenGroup) | Out-Null
    }

     if ($groupArray.Count -eq 0) {
        return ,@()         
    }
    # Return the data back to the caller
        return, $groupArray

        
}

function GetUsers{

    param($grps)

    for ($i = 0; $i -lt $users_num; $i++) {


        $fname =  $global:firstname |Get-Random
        $lname =  $global:lastname | Get-Random
        $passwd = $global:password | Get-Random
        $get_random = $grps | Get-Random

        #Generating Hashtables for new users
        $new_users = @{

            "name" = "$fname $lname"
            "groups" = @(($get_random).name)
            "password" = "$passwd"
            
        }
    $global:users += $new_users

    $global:firstname.Remove($fname) | Out-Null
    $global:lastname.Remove($lname) | Out-Null
    $global:password.Remove($passwd) | Out-Null
    }

}

function Domain {

     $domain = ([ordered] @{
        
        "domain" = "samchi_seclab.local"
        "users" = $global:users
        "groups" = $global:group
        
        
    } ) #Out-File -FilePath $JSONFile
    ConvertTo-Json -InputObject $domain -Depth 5| Out-File -FilePath $JSONFile
}



 # Generate the groups, return them, and assign them directly to the group array list
$UserGroup = Getgroup $global:groups

# Pass the fresh groups directly to the users script generator
GetUsers -grps $UserGroup

# Export the finished arrays to the domain configuration file
Domain
$global:users
