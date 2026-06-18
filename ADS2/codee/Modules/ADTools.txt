@{
    # General module info
    RootModule        = ''
    ModuleVersion     = '1.0.0'
    GUID              = 'd0f7c1a6-8f2b-4b9a-9f5a-0e6e2c3a1b2c'
    Author            = 'Ekwueme'
    CompanyName       = 'HomeLab'
    Description       = 'PowerShell toolkit for managing an Active Directory home lab.'
    Copyright         = '(c) 2026'

    # Modules to load (relative paths from this .psd1 location)
    # Hold_Envariables is loaded first as it provides helper functions used by other modules
    NestedModules     = @(
        '..\code\Modules\Hold_Envariables.psm1',
        '..\code\Modules\password_security_policy.psm1',
        '..\code\Modules\root_schema_generator.psm1',
        '..\code\Modules\installAD.psm1',
        '..\code\Modules\CreateUsers.psm1',
        '..\code\Modules\CreateGroups.psm1',
        '..\code\Modules\OU.psm1',
        '..\code\Modules\users.psm1'
    )

    # Functions exported by all modules
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

    # Cmdlets, variables, aliases
    CmdletsToExport   = @()
    VariablesToExport = '*'
    AliasesToExport   = '*'

    # Compatibility
    PowerShellVersion = '5.1'

    # Additional metadata
    PrivateData = @{
        PSData = @{
            Tags = @('AD', 'ActiveDirectory', 'HomeLab', 'Setup')
            LicenseUri = ''
            ProjectUri = ''
        }
    }
}
