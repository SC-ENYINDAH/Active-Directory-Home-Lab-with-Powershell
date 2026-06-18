param(
    [string]$DomainName = "home.local",
    [string]$SafeModeAdministratorPassword,
    [string]$GroupsFile = ".\code\data\Groups.tst",
    [string]$UsersFile = ".\code\data\Users.tst"
)

$moduleManifest = Join-Path -Path $PSScriptRoot -ChildPath 'ActiveDirectoryHome.psd1'
if (-not (Test-Path $moduleManifest)) {
    throw "Module manifest not found: $moduleManifest"
}

Write-Host "[+] Loading Active Directory lab module from $moduleManifest" -ForegroundColor Green
Import-Module $moduleManifest -Force -ErrorAction Stop

Write-Host "[+] Installing Active Directory Domain Services role" -ForegroundColor Cyan
Install-ADDS

Write-Host "[+] Promoting this server to domain controller for $DomainName" -ForegroundColor Cyan
Promote-DomainController -DomainName $DomainName -SafeModeAdministratorPassword $SafeModeAdministratorPassword

Write-Host "[+] Importing lab groups from $GroupsFile" -ForegroundColor Cyan
Import-LabGroups -FilePath $GroupsFile

Write-Host "[+] Importing lab users from $UsersFile" -ForegroundColor Cyan
Import-LabUsers -FilePath $UsersFile -DefaultDomainName $DomainName

Write-Host "[+] Applying lab security policies" -ForegroundColor Cyan
Set-LabLockoutPolicy -Threshold 5 -Duration 30 -Window 15
Set-LabPasswordPolicy -MinLength 12 -HistoryCount 24 -MaxAge 60 -MinAge 1

Write-Host "[+] Displaying current domain policy and account state" -ForegroundColor Cyan
Show-LabPasswordPolicy
Show-LabLockedAccounts
Show-LabEnabledUsers

Write-Host "[+] Active Directory lab runner complete." -ForegroundColor Green
