<#
.SYNOPSIS
    This checks for compliancy on V-81495

.PARAMETER BeginData
    Input data as returned by the begin.ps1 script for this stig. Maybe null if one is not provided.
#>
Param($BeginData)
Write-Verbose "V-81495"
$Details = ""
$Comments = ""
$Result = "NotAFinding"

#Perform necessary check
$Key32 = Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319\SchUseStrongCrypto" -Name "SchUseStrongCrypto" -ErrorAction SilentlyContinue
$Key64 = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319\SchUseStrongCrypto" -Name "SchUseStrongCrypto" -ErrorAction SilentlyContinue

if ($Key32 -eq $null) {
    $Details += "Key does not exist for WOW6432Node.`r`n"
    $Result="Open"
} elseif ($Key32.SchUseStrongCrypto -ne 1) {
    $Details += "Key is not set to '1' for WOW6432Node.`r`n"
    $Result="Open"
} else {
    $Details += "WOW6432Node key is good.`r`n"
}
if ($Key64 -eq $null) {
    $Details += "Key does not exist for native software node.`r`n"
    $Result="Open"
} elseif ($Key64.SchUseStrongCrypto -ne 1) {
    $Details += "Key is not set to '1' for native software node.`r`n"
    $Result="Open"
} else {
    $Details += "Native software key is good.`r`n"
}

#Return results
return @{Details=$Details;
        Comments=$Comments;
        Result=$Result}