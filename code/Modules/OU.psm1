
param (
    [string]$JSONFile
)
$baseDir = if ($PSScriptRoot) { $PSScriptRoot } else { Get-Location }

$RootPath = Get-ChildItem -Path $baseDir -Filter "Hold_Envariable.psm1" -Recurse -File
Import-Module $RootPath -Force

if (-not $JSONFile) {
    $JSONFile = Get-ChildItem -Path $baseDir -Filter "ad_schema.json" -Recurse -File
}
function Initialize-OUs {
    param([string]$JSONFile)

    $schema     = Get-Content $JSONFile -Raw | ConvertFrom-Json
    $DomainName = $schema.domain
    $domainPath = Get-DomainPath -DomainName $DomainName

    # Root OUs
    New-ADOrganizationalUnit -Name "Users" -Path $domainPath -ErrorAction SilentlyContinue
    New-ADOrganizationalUnit -Name "Groups" -Path $domainPath -ErrorAction SilentlyContinue

    # get department names dynamically from the schema groups
    foreach ($dept in $schema.groups.name) {
        New-ADOrganizationalUnit -Name $dept -Path "OU=Users,$domainPath" -ErrorAction SilentlyContinue
        New-ADOrganizationalUnit -Name $dept -Path "OU=Groups,$domainPath" -ErrorAction SilentlyContinue
    }
}

#Initialize-OUs -JSONFile $JSONFile
