Write-Output "===== Domain Password Policy ====="
Get-ADDefaultDomainPasswordPolicy | Format-List

Write-Output "`n===== Locked Out Accounts ====="
Search-ADAccount -LockedOut | Select-Object Name, SamAccountName, LockedOut

Write-Output "`n===== Enabled Users ====="
Get-ADUser -Filter {Enabled -eq $true} | Select-Object Name, SamAccountName

Write-Output "`n===== Recent Login Failures ====="
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625} -MaxEvents 20 |
Select-Object TimeCreated, @{Name='User';Expression={$_.Properties[5].Value}}, @{Name='IP';Expression={$_.Properties[18].Value}}

Write-Output "`n===== Summary ====="
$lockedOutCount = (Search-ADAccount -LockedOut).Count
$enabledUsersCount = (Get-ADUser -Filter {Enabled -eq $true}).Count
$failedLoginsCount = (Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625} -MaxEvents 100).Count

Write-Output "Locked Out Accounts: $lockedOutCount"
Write-Output "Enabled Users: $enabledUsersCount"
Write-Output "Failed Logins (last 100 events): $failedLoginsCount"
