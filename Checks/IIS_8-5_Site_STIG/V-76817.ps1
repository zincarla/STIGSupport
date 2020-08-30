Param($BeginData)
Write-Verbose "V-100227"

$Result = "NotAFinding"
$Details = ""
$Comments = ""

Import-Module WebAdministration;
$CheckResult = (Get-WebConfigurationProperty "system.webServer/security/requestFiltering" -name requestLimits -PSPath "IIS:\Sites\$($BeginData.Site)").maxUrl

if ($CheckResult -ne $null)
{
    $Details+=$CheckResult.ToString()
    if ($CheckResult -gt 4096) {
        $Result="Open"
    }
} else {
    $Result="Not_Reviewed"
    $Details+="Web config could not be queried. "
}

return @{Details=$Details;
            Comments=$Comments;
            Result=$Result}