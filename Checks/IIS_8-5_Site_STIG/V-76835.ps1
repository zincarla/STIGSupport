Param($BeginData)
Write-Verbose "V-100241"

$Result = "NotAFinding"
$Details = ""
$Comments = ""


Import-Module WebAdministration;
$CheckResult = (Get-WebConfigurationProperty "system.webServer/httpErrors" -name errorMode -PSPath "IIS:\Sites\$($BeginData.Site)")

if ($CheckResult -ne $null)
{
    $Details+=$CheckResult
    if ($CheckResult -ne "DetailedLocalOnly") {
        $Result="Open"
    }
} else {
    $Result="Not_Reviewed"
    $Details+="Web config could not be queried. "
}

return @{Details=$Details;
            Comments=$Comments;
            Result=$Result}