
Import-Module (Join-Path $PSScriptRoot "Modules\root_schema_generator.psm1")
Import-Module (Join-Path $PSScriptRoot "Modules\password_security_policy.psm1")


function Install-ADDService {
    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
}

function Promote-ADController {
    param(
        [string]$JSONFile = "$PSScriptRoot\ad_schema.json"   
    )
    $GetJSONFile = Get-Content $JSONFile -Raw | ConvertFrom-Json
    $DomainName = $GetJSONFile.domain
    $AdminPassword = $GetJSONFile.SafeModeAdministratorPassword

    Write-Output "[+] Promoting domain controller for $DomainName" -ForegroundColor Green

    $SafeModePassword = ConvertTo-SecureString $AdminPassword -AsPlainText -Force

    Install-ADDSForest -DomainName $DomainName -SafeModeAdministratorPassword $SafeModePassword -Force


    Install-ADDSForest -DomainName $DomainName -Force

    Write-Log "Promoted domain controller for $DomainName" "SUCCESS"


    Set-AccountLockoutPolicy 
    Set-PasswordSecPolicy
    GetInput
}

Export-ModuleMember -Function Install-ADDService, Promote-ADController