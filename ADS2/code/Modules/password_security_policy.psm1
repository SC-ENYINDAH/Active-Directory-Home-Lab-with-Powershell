function Set-AccountLockoutPolicy {
    param(
        [int]$Threshold = 3,
        [int]$Duration = 60,
        [int]$Window = 15
    )
    Set-ADDefaultDomainPasswordPolicy -LockoutThreshold $Threshold `
        -LockoutDuration $Duration -LockoutObservationWindow $Window
}
function Set-PasswordSecPolicy {
    param(
        [int]$MinLength = 12,
        [int]$HistoryCount = 24,
        [int]$MaxAge = 60,
        [int]$MinAge = 1
    )
    Set-ADDefaultDomainPasswordPolicy -MinPasswordLength $MinLength `
        -PasswordHistoryCount $HistoryCount -MaxPasswordAge $MaxAge `
        -MinPasswordAge $MinAge -ComplexityEnabled $true
}

Export-ModuleMember -Function `
Set-AccountLockoutPolicy, `
Set-PasswordSecPolicy
