Set-StrictMode -Version Latest

function Get-PasswordPolicyAudit {

    Get-ADDefaultDomainPasswordPolicy |
    Select-Object `
        ComplexityEnabled,
        LockoutThreshold,
        LockoutDuration,
        MinPasswordLength,
        PasswordHistoryCount,
        MaxPasswordAge
}

function Get-DomainAdminsAudit {

    Get-ADGroupMember `
        "Domain Admins" |

    Select-Object `
        Name,
        SamAccountName,
        ObjectClass
}

function Get-LockedAccountsAudit {

    Search-ADAccount `
        -LockedOut |

    Select-Object `
        Name,
        SamAccountName
}

function Get-StaleAccountsAudit {

    Get-ADUser `
        -Filter * `
        -Properties LastLogonDate |

    Where-Object {

        $_.LastLogonDate -lt
        (Get-Date).AddDays(-90)
    } |

    Select-Object `
        Name,
        SamAccountName,
        LastLogonDate
}

function Get-PrivilegedGroupsAudit {

    @(
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Administrators"
    ) |
    ForEach-Object {

        [PSCustomObject]@{

            Group = $_

            Members =
                (
                    Get-ADGroupMember $_ |
                    Select-Object -Expand Name
                )
        }
    }
}

function Invoke-SecurityAudit {

    [PSCustomObject]@{

        Timestamp =
            Get-Date

        PasswordPolicy =
            Get-PasswordPolicyAudit

        LockedAccounts =
            Get-LockedAccountsAudit

        StaleAccounts =
            Get-StaleAccountsAudit

        DomainAdmins =
            Get-DomainAdminsAudit

        PrivilegedGroups =
            Get-PrivilegedGroupsAudit
    }
}

function Export-AuditReport {

    $Report =
        Invoke-SecurityAudit

    $File =
        Join-Path `
            "$PSScriptRoot\..\Reports" `
            (
                "Audit-" +
                (Get-Date -Format yyyyMMddHHmmss) +
                ".json"
            )

    $Report |
    ConvertTo-Json -Depth 30 |
    Set-Content $File

    return $File
}

Export-ModuleMember -Function *