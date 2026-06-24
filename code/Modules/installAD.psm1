$baseDir = if ($PSScriptRoot) { $PSScriptRoot } else { Get-Location }

function Install-ADDService {
    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
}

function Promote-DomainController {
    param(
        [Parameter(Mandatory=$false)]
        [string]$DomainName,
        [string]$SafeModeAdministratorPassword,
        [string]$JSONFile
    )

    if (-not $JSONFile) {
        $JSONFile = Get-ChildItem -Path $baseDir -Filter "ad_schema.json" -Recurse -File
    }

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
    Write-Host "[+] Promoted domain controller for $DomainName" -ForegroundColor Green
}

Export-ModuleMember -Function `
Install-ADDService, `
Promote-DomainController