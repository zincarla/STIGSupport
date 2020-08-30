Param($BeginData)
Write-Verbose "V-100247"

$Result = "NotAFinding"
$Details = ""
$Comments = ""

Import-Module WebAdministration;
$CheckResult = (Get-WebConfigurationProperty "/system.web/sessionState" -name timeout -PSPath "IIS:\Sites\$($BeginData.Site)").Value.TotalMinutes

if ($CheckResult -ne $null)
{
    $Details+=$CheckResult
    if ($CheckResult -gt 20) {
        $Result="Open"
    }
} else {
    $Result="Not_Reviewed"
    $Details+="Web config could not be queried. "
}

return @{Details=$Details;
            Comments=$Comments;
            Result=$Result}