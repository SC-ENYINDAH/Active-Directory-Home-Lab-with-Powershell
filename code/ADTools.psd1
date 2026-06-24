@{
    RootModule        = ''
    ModuleVersion     = '1.0.0'
    GUID              = 'd0f7c1a6-8f2b-4b9a-9f5a-0e6e2c3a1b2c'
    Author            = 'Sampson Chinecherem Enyindah'
    CompanyName       = 'HomeLab'
    Description       = 'PowerShell toolkit for managing an Active Directory home lab.'
    Copyright         = '(c) 2026'


    NestedModules     = @()

    FunctionsToExport = @(
        'Install-ADDService',
        'Promote-ADController',
        'Create-ADGroup',
        'Add-UserToADGroup',
        'CreateADUser',
        'CreateUser_Handle_JSONFile',
        'Initialize-OUs',
        'Set-AccountLockoutPolicy',
        'Set-PasswordSecPolicy',
        'Get-SamAccountName',
        'Get-UserPrincipalName',
        'Get-GroupPath',
        'Get-DomainPath',
        'GetInput',
        'EnhacePassword',
        'CreateGroup',
        'GetUsers',
        'Domain'
    )

    CmdletsToExport   = @()
    VariablesToExport = '*'
    AliasesToExport   = '*'

    PowerShellVersion = '5.1'

    PrivateData = @{
        PSData = @{
            Tags = @('AD', 'ActiveDirectory', 'HomeLab', 'Setup')
            LicenseUri = ''
            ProjectUri = ''
        }
    }
}

