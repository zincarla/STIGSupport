Param($BeginData)
Write-Verbose "V-100257"

$Result = "NotAFinding"
$Details = ""
$Comments = ""

Import-Module WebAdministration;
$CheckResult = (Get-WebConfigurationProperty "/system.webServer/security/access" -name sslFlags -PSPath "IIS:\Sites\$($BeginData.Site)")
if ($CheckResult.GetType().Name -eq "ConfigurationAttribute") {
    $CheckResult = $CheckResult.Value.ToString()
}

if ($CheckResult -ne $null)
{
    $Details+=$CheckResult
    $TestArray = $CheckResult.ToLower().Split(",")
    if (-not ($TestArray.Contains("ssl") -and $TestArray.Contains("sslnegotiatecert") -and $TestArray.Contains("sslrequirecert") -and $TestArray.Contains("ssl128"))) {
        $Result = "Open"
    }
} else {
    $Result="Not_Reviewed"
    $Details+="Web config could not be queried. "
}

return @{Details=$Details;
            Comments=$Comments;
            Result=$Result}