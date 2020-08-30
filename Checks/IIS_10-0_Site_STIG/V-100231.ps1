Param($BeginData)
Write-Verbose "V-100231"

$Result = "NotAFinding"
$Details = ""
$Comments = ""

Import-Module WebAdministration;
$CheckResult = (Get-WebConfigurationProperty "system.webServer/security/requestFiltering" -name requestLimits -PSPath "IIS:\Sites\$($BeginData.Site)").maxQueryString

if ($CheckResult -ne $null)
{
    $Details+=$CheckResult.ToString()
    if ($CheckResult -gt 2048) {
        $Result="Open"
    }
} else {
    $Result="Not_Reviewed"
    $Details+="Web config could not be queried. "
}

return @{Details=$Details;
            Comments=$Comments;
            Result=$Result}