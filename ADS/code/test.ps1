param(
    #[Parameter(Mandatory=$true)]$JSONFile,
    [string]$JSONFile = (Join-Path $PSScriptRoot "out.json"),
    [switch]$undo
)

# 1. Properly target data paths relative to script location
$firstname = [System.Collections.ArrayList](Get-Content "$PSScriptRoot\data\first_names.txt")
$lastname  = [System.Collections.ArrayList](Get-Content "$PSScriptRoot\data\last_names.txt")
$password  = [System.Collections.ArrayList](Get-Content "$PSScriptRoot\data\passwords.txt")
$groups    = [System.Collections.ArrayList](Get-Content "$PSScriptRoot\data\group_names.txt")

$grp_num = 10
$users_num = 100

function Get-GeneratedGroups {
    param(
        $availableGroups,
        [int]$count
    )
    # Initialize a local array explicitly
    $groupArray = @()

    for ($i = 0; $i -lt $count; $i++) {
        if ($availableGroups.Count -eq 0) { break }

        $chosenGroup = (Get-Random -InputObject $availableGroups)
        
        # Append the hashtable to our local array
        $groupArray += @{ "name" = "$chosenGroup" }

        # Remove the created group so it isn't picked again
        $availableGroups.Remove($chosenGroup) | Out-Null
    }
    # Return the data back to the caller
    return $groupArray
}

function Get-GeneratedUsers {
    param(
        $grps,
        $firstNamesList,
        $lastNamesList,
        $passwordsList,
        [int]$count
    )
    # Initialize a local array explicitly
    $userArray = @()

    for ($i = 0; $i -lt $count; $i++) {
        # Avoid crashing if we run out of unique names
        if ($firstNamesList.Count -eq 0 -or $lastNamesList.Count -eq 0) {
            Write-Warning "Ran out of unique names! Stopping loop early."
            break
        }

        $fname  = (Get-Random -InputObject $firstNamesList)
        $lname  = (Get-Random -InputObject $lastNamesList)
        $passwd = (Get-Random -InputObject $passwordsList)

        # Generating Hashtables for new users
        $new_user = @{
            "name"     = "$fname, $lname"
            "groups"   = @((Get-Random -InputObject $grps).name)
            "password" = "$passwd"
        }
        $userArray += $new_user

        # Remove used names INSIDE the loop to guarantee uniqueness
        $firstNamesList.Remove($fname) | Out-Null
        $lastNamesList.Remove($lname) | Out-Null
    }
    return $userArray
}

function Get-DomainConfig {
    param($userData, $groupData)

    $domain = @{
        "domain" = "samchi_seclab.local"
        "users"  = $userData
        "groups" = $groupData
    }
    ConvertTo-Json -InputObject $domain -Depth 4 | Out-File -FilePath $JSONFile
}

# 2. Execution Flow: Pass parameters explicitly and capture the outputs
$myGenGroup = Get-GeneratedGroups -availableGroups $groups -count $grp_num
$myUsers    = Get-GeneratedUsers -grps $myGenGroup -firstNamesList $firstname -lastNamesList $lastname -passwordsList $password -count $users_num
$mydomain   = Get-DomainConfig -userData $myUsers -groupData $myGenGroup

# 3. Output to verify it works
$mydomain
