Import-Module .\ADTools.psd1 -Force

param(
    [string]$Action = "All",
    [string]$JSONFile,
    [string]$LogFile
)

if (-not $JSONFile) {
    $JSONFile = Join-Path $PSScriptRoot "ad_schema.json"
}
if (-not $LogFile) {
    $LogFile = Join-Path $PSScriptRoot "runner.log"
}

$schema = Get-Content $JSONFile -Raw | ConvertFrom-Json

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )

    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $entry = "$timestamp [$Level] $Message"

    try {
        Add-Content -Path $LogFile -Value $entry
    }
    catch {
        Write-Warning "Unable to write to log file: $LogFile. $_"
    }

    $color = switch ($Level) {
        'SUCCESS' { 'Green' }
        'ERROR'   { 'Red' }
        'WARN'    { 'Yellow' }
        default   { 'White' }
    }

    Write-Host $entry -ForegroundColor $color
}

# Wrapper with duration tracking
function Run-Step {

    param(
        [string]$StepName, 
        [scriptblock]$ActionBlock
    )

    Write-Log "Starting step: $StepName"
    $start = Get-Date

    try {
        & $ActionBlock
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

# --- Orchestration ---
switch ($Action) {
    "Domain"   { 
        Run-Step "Install AD DS" { Install-ADDService } 
        Run-Step "Promote Domain Controller" { Promote-DomainController -DomainName $schema.domain } 
    }
    "OUs"      { 
        Run-Step "Initialize OUs" { Initialize-OUs -JSONFile $JSONFile } 
    }
    "Groups"   { 
        Run-Step "Create Groups" { Run-GroupCreation } 
    }
    "Users"    { 
        Run-Step "Create Users" { Run-UserCreation } 
    }
    "Policies" { 
        Run-Step "Set Lockout Policy" { Set-AccountLockoutPolicy }; 
        Run-Step "Set Password Policy" { Set-PasswordSecPolicy } 
    }
    "All"      {
        Run-Step "Install AD DS" { Install-ADDService }
        Run-Step "Promote Domain Controller" { Promote-DomainController -DomainName $schema.domain }
        Run-Step "Initialize OUs" { Initialize-OUs -JSONFile $JSONFile }
        Run-Step "Create Groups" { Run-GroupCreation }
        Run-Step "Create Users" { Run-UserCreation }
        Run-Step "Set Lockout Policy" { Set-AccountLockoutPolicy -Threshold 5 -Duration 30 -Window 15 }
        Run-Step "Set Password Policy" { Set-PasswordSecPolicy -MinLength 12 -HistoryCount 24 -MaxAge 60 -MinAge 1 }
    }
    default    { Write-Log "Unknown action specified: $Action" "WARN" }
}

Run-Step 'Verification' {
    Get-ADUser -Filter * | Select-Object Name, SamAccountName, Enabled | Format-Table
    Get-ADGroup -Filter * | Select-Object Name | Format-Table
    Get-ADOrganizationalUnit -Filter * | Select-Object Name | Format-Table
    Get-ADDefaultDomainPasswordPolicy | Format-List
}
