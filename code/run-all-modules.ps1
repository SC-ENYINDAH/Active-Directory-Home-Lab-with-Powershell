[CmdletBinding()]

param(
    [string]$Action,
    [string]$JSONFile,
    [string]$LogFile
)


$baseDir = if ($PSScriptRoot) { $PSScriptRoot } else { Get-Location }

$RootPath = Get-ChildItem -Path $baseDir -Filter "ADTools.psd1" -Recurse -File


Import-Module $RootPath -Force

if (-not $JSONFile) {
    $JSONFile = Get-ChildItem -Path $baseDir -Filter "ad_schema.json" -Recurse -File
}
if (-not $LogFile) {
    $LogFile = Get-ChildItem -Path $baseDir -Filter "ad_schema.json" -Recurse -File
}

$schema = Get-Content $JSONFile -Raw | ConvertFrom-Json

function Get-AllModules{

    # Modules in the order they should be executed
    $orderedModules = @(
        "root_schema_generator.psm1",          # 1. Root schema generator
        "Hold_Envariables.psm1"                 # 2. Hold Envariables
        "installAD.psm1",                      # 3. Domain Controller Setup
        "password_security_policy.psm1",       # 4. Policies Setup
        "CreateUsers.psm1",                    # 5. Users Setup
        "CreateGroups.psm1",                   # 6. Groups Setup
        "OU.psm1"                              # 7. Organizational Units Setup
    )
    
    # Get all .psm1 files recursively
    $Modules = Get-ChildItem -Path $baseDir -Filter '*.psm1' -Recurse -File

    # Loop through and import each module
    foreach ($moduleName in $orderedModules) {
        $module = $Modules | Where-Object { $_.Name -eq $moduleName }
        if ($module) {
            Write-Host "Importing module: $($module.FullName)"
            Import-Module $module.FullName -Force
        } else {
        Write-Warning "Module $moduleName not found!"
        }
    }
   
}

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )

    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $entry = "$timestamp [$Level] $Message"

    
    Add-Content -Path $LogFile -Value $entry

    $color = switch ($Level) {
        'SUCCESS' { 'Green' }
        'ERROR'   { 'Red' }
        'WARN'    { 'Yellow' }
        default   { 'White' }
    }

    Write-Host $entry -ForegroundColor $color
}

# Duration tracking
function Run-Step {

    param(
        [string]$StepName, 
        [scriptblock]$ActionBlock
    )

    Write-Log "Starting step: $StepName"
    $start = Get-Date

    try {
        & $ActionBlock
        $end = Get-Date
        $duration = ($end - $start).TotalSeconds
        Write-Log "Step $StepName completed successfully in $duration seconds" "SUCCESS"
    }
    catch {
        $duration = ($end - $start).TotalSeconds
        Write-Log "Step $StepName failed after $duration seconds: $_" "ERROR"
    }
}

# --- Per-object logging wrappers ---
function Run-UserCreation {
    foreach ($user in $schema.users) {
        $start = Get-Date
        try {
            CreateADUser $user
            $duration = ((Get-Date) - $start).TotalSeconds
            Write-Log "User $($user.name) created successfully in $($user.ou) (Duration: $duration sec)" "SUCCESS"
        }
        catch {
            $duration = ((Get-Date) - $start).TotalSeconds
            Write-Log "Failed to create user $($user.name) after $duration sec: $_" "ERROR"
        }
    }
}

function Run-GroupCreation {
    foreach ($group in $schema.groups) {
        $start = Get-Date
        try {
            Create-ADGroup -groupObject $group -DomainName $schema.domain
            $duration = ((Get-Date) - $start).TotalSeconds
            Write-Log "Group $($group.name) created successfully in $($group.path) (Duration: $duration sec)" "SUCCESS"
        }
        catch {
            $duration = ((Get-Date) - $start).TotalSeconds
            Write-Log "Failed to create group $($group.name) after $duration sec: $_" "ERROR"
        }
    }

    foreach ($user in $schema.users) {
        foreach ($grp in $user.groups) {
            $start = Get-Date
            try {
                Add-UserToADGroup -GroupName $grp -UserSam (Get-SamAccountName -FullName $user.name)
                $duration = ((Get-Date) - $start).TotalSeconds
                Write-Log "User $($user.name) added to group $grp (Duration: $duration sec)" "SUCCESS"
            }
            catch {
                $duration = ((Get-Date) - $start).TotalSeconds
                Write-Log "Failed to add $($user.name) to group $grp after $duration sec: $_" "ERROR"
            }
        }
    }
}


#==================Input Gathering========================

while ($true) {
Clear-Host
Get-AllModules

    $choice = ([order]@" 
        [1] Domain Controller Setup
        [2] Policies Setup
        [3] Users Setup
        [4] Groups Setup
        [5] Organizational Units (OUs) Setup
        [6] All of the Above
        [q] Quit...

"@
    )
    Write-Host "  ==== Starting Active Directory Deployment === =" -ForegroundColor Cyan
    Write-Host " "
    Write-Host "  ==== Please select the action you want to perform === =" -ForegroundColor Cyan
    Write-Host $choice -ForegroundColor Yellow
    $Get = Read-Host 

    $Action = if ($Get) {
        $Get.Trim().ToLower()
    
    }else {''}


    switch ($Action) {
        "1"   { 
            Run-Step "Install AD DS" { Install-ADDService } 
            Run-Step "Promote Domain Controller" { Promote-DomainController -DomainName $schema.domain } 
        }
        "2" { 
            Run-Step "Set Lockout Policy" { Set-AccountLockoutPolicy }; 
            Run-Step "Set Password Policy" { Set-PasswordSecPolicy } 
        }
        "3"    { 
            Run-Step "Create Users" { Run-UserCreation } 
        }  
        "4"   { 
            Run-Step "Create Groups" { Run-GroupCreation } 
        }  
        "5"      { 
            Run-Step "Initialize OUs" { Initialize-OUs -JSONFile $JSONFile } 
        }
        "6"      {
        Run-Step "Install AD DS" { Install-ADDService }
        Run-Step "Set Lockout Policy" { Set-AccountLockoutPolicy}
        Run-Step "Set Password Policy" { Set-PasswordSecPolicy  }
        Run-Step "Promote Domain Controller" { Promote-DomainController -DomainName $schema.domain }
        Run-Step "Create Groups" { Run-GroupCreation }
        Run-Step "Create Users" { Run-UserCreation }
        Run-Step "Initialize OUs" { Initialize-OUs -JSONFile $JSONFile }      
        }
        "q"        { 
            Write-Log "Exiting the script as per user request." "INFO"
            break 
        }
        default    { Write-Log "Unknown action specified: $Action" "WARN"; Start-Sleep -Seconds 2 }
    }

    Run-Step 'Verification' {
        Get-ADUser -Filter * | Select-Object Name, SamAccountName, Enabled | Format-Table
        Get-ADGroup -Filter * | Select-Object Name | Format-Table
        Get-ADOrganizationalUnit -Filter * | Select-Object Name | Format-Table
        Get-ADDefaultDomainPasswordPolicy | Format-List
    }

}

