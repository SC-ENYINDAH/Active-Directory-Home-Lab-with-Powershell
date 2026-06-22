function Get-SamAccountName {
    param([string]$FullName)
    $firstname, $lastname = $FullName.Split(" ")
    $UserName = ($firstname[0] + $lastname).ToLower()
    return $UserName
}

function Get-UserPrincipalName {
    param(
        [string]$samAccountName,
        [string]$DomainName
    )
    return "$samAccountName@$DomainName"
}

function Get-GroupPath {
    param([string]$DomainName)
    $parts = $DomainName.Split(".")
    return "OU=Groups," + ($parts | ForEach-Object { "DC=$_" } -join ",")
}
function Get-DomainPath {
    param([string]$DomainName)
    return ($DomainName -split '\.') | ForEach-Object { "DC=$_" } -join ","
}

Export-ModuleMember -Function `
Get-SamAccountName, `
Get-UserPrincipalName, `
Get-GroupPath, `
Get-DomainPath
