param(
    [string]$JSONFile = "$PSScriptRoot\ad_schema.json"
)

Import-Module ActiveDirectory -ErrorAction SilentlyContinue
Import-Module ADDSDeployment -ErrorAction SilentlyContinue

function Install-ADDS {
    Install-ADDService
}

function Promote-DomainController {
    param(
        [Parameter(Mandatory=$false)]
        [string]$DomainName,
        [string]$SafeModeAdministratorPassword,
        [string]$JSONFile = "$PSScriptRoot\ad_schema.json"
    )

    if (-not $DomainName) {
        if (Test-Path $JSONFile) {
            $json = Get-Content $JSONFile -Raw | ConvertFrom-Json
            $DomainName = $json.domain
        }
    }

    if (-not $DomainName) {
        throw "DomainName is required for Promote-DomainController."
    }

    if (-not $SafeModeAdministratorPassword) {
        $securePassword = Read-Host -Prompt "Enter SafeMode Administrator Password" -AsSecureString
    }
    else {
        $securePassword = ConvertTo-SecureString -String $SafeModeAdministratorPassword -AsPlainText -Force
    }

    Write-Host "[+] Promoting domain controller for $DomainName" -ForegroundColor Green
    Install-ADDSForest -DomainName $DomainName -SafeModeAdministratorPassword $securePassword -Force
    Write-Host "[+] Domain controller promotion completed for $DomainName" -ForegroundColor Green
}

function Get-ImportFileContent {
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )

    if (-not (Test-Path $FilePath)) {
        throw "File not found: $FilePath"
    }

    $ext = [IO.Path]::GetExtension($FilePath).ToLower()

    switch ($ext) {
        '.json' { return Get-Content $FilePath -Raw | ConvertFrom-Json }
        '.csv' { return Import-Csv -Path $FilePath }
        '.tsv' { return Import-Csv -Path $FilePath -Delimiter "`t" }
        default {
            $lines = Get-Content $FilePath | Where-Object { $_.Trim() -ne '' }
            if ($lines.Count -eq 0) {
                return @()
            }

            if ($lines[0] -match ',') {
                return $lines | ConvertFrom-Csv
            }

            if ($lines[0] -match "`t") {
                return $lines | ConvertFrom-Csv -Delimiter "`t"
            }

            return $lines | ForEach-Object { [PSCustomObject]@{ name = $_.Trim() } }
        }
    }
}

function Normalize-ImportRecord {
    param(
        [Parameter(Mandatory=$true)]
        $Entry
    )

    if (-not $Entry) {
        return $null
    }

    return [PSCustomObject]@{
        name     = $Entry.name  ?? $Entry.Name
        password = $Entry.password ?? $Entry.Password
        ou       = $Entry.ou ?? $Entry.OU
        groups   = $Entry.groups ?? $Entry.Groups
        path     = $Entry.path ?? $Entry.Path
        domain   = $Entry.domain ?? $Entry.Domain
    }
}

function Import-LabGroups {
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )

    $data = Get-ImportFileContent -FilePath $FilePath
    if (-not $data) {
        Write-Warning "No group data found in $FilePath"
        return
    }

    $groups = if ($data.PSObject.Properties.Name -contains 'groups') { $data.groups } else { $data }

    foreach ($entry in $groups) {
        $group = Normalize-ImportRecord -Entry $entry
        if (-not $group.name) {
            continue
        }

        Create-ADGroup -groupObject @{ name = $group.name; path = $group.path }
    }
}

function Import-LabUsers {
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath,
        [string]$DefaultDomainName
    )

    $data = Get-ImportFileContent -FilePath $FilePath
    if (-not $data) {
        Write-Warning "No user data found in $FilePath"
        return
    }

    if ($data.PSObject.Properties.Name -contains 'users') {
        if (-not $global:DomainName -and $data.domain) {
            $global:DomainName = $data.domain
        }
        $users = $data.users
    }
    else {
        $users = $data
    }

    if (-not $global:DomainName -and $DefaultDomainName) {
        $global:DomainName = $DefaultDomainName
    }

    foreach ($entry in $users) {
        $user = Normalize-ImportRecord -Entry $entry
        if (-not $user.name) {
            continue
        }

        if (-not $user.ou -and $global:DomainName) {
            $user.ou = "OU=Users," + (Get-DomainPath -DomainName $global:DomainName)
        }

        CreateADUser -UserObject ([PSCustomObject]@{
            name     = $user.name
            password = $user.password
            ou       = $user.ou
            groups   = $user.groups
        })

        if ($user.groups) {
            $groupNames = if ($user.groups -is [string]) {
                $user.groups -split ';' | ForEach-Object { $_.Trim() }
            }
            else {
                $user.groups
            }

            foreach ($groupName in $groupNames) {
                if ($groupName) {
                    Add-UserToADGroup -GroupName $groupName -UserSam (Get-SamAccountName -FullName $user.name)
                }
            }
        }
    }
}

function Set-LabLockoutPolicy {
    param(
        [int]$Threshold = 5,
        [int]$Duration = 30,
        [int]$Window = 15
    )

    Set-AccountLockoutPolicy -Threshold $Threshold -Duration $Duration -Window $Window
}

function Set-LabPasswordPolicy {
    param(
        [int]$MinLength = 12,
        [int]$HistoryCount = 24,
        [int]$MaxAge = 60,
        [int]$MinAge = 1
    )

    Set-PasswordSecPolicy -MinLength $MinLength -HistoryCount $HistoryCount -MaxAge $MaxAge -MinAge $MinAge
}

function Show-LabPasswordPolicy {
    Get-ADDefaultDomainPasswordPolicy | Format-List
}

function Show-LabLockedAccounts {
    Search-ADAccount -LockedOut -UsersOnly | Select-Object Name, SamAccountName, DistinguishedName
}

function Show-LabEnabledUsers {
    Get-ADUser -Filter { Enabled -eq $true } -Properties Enabled | Select-Object Name, SamAccountName, UserPrincipalName, Enabled
}

Export-ModuleMember -Function 
    Install-ADDS,
    Promote-DomainController,
    Import-LabUsers,
    Import-LabGroups,
    Set-LabLockoutPolicy,
    Set-LabPasswordPolicy,
    Show-LabPasswordPolicy,
    Show-LabLockedAccounts,
    Show-LabEnabledUsers
