Param($BeginData)
Write-Verbose "V-100219"

$Result = "NotAFinding"
$Details = ""
$Comments = ""

Import-Module WebAdministration;
$CheckResult = (Get-WebConfigurationProperty "/system.webServer/security/access" -name sslFlags -PSPath "IIS:\Sites\$($BeginData.Site)" -ErrorAction SilentlyContinue)
if ($CheckResult.GetType().Name -eq "ConfigurationAttribute") {
    $CheckResult = $CheckResult.Value.ToString()
}

if ($CheckResult -ne $null)
{
    $Details+=$CheckResult
    $TestArray = $CheckResult.ToLower().Split(",")
    if (-not $TestArray.Contains("sslrequirecert")) {
        $Result="Open"
    }
} else {
    $Result="Not_Reviewed"
    $Details+="Web config could not be queried. "
}

return @{Details=$Details;
            Comments=$Comments;
            Result=$Result}