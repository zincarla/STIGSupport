Param($BeginData)
Write-Verbose "V-100193"

$Result = "NotAFinding"
$Details = ""
$Comments = ""

Import-Module WebAdministration;
$CheckResult = (Get-WebConfigurationProperty "/system.web/sessionState" -name cookieless -PSPath "IIS:\Sites\$($BeginData.Site)" -ErrorAction SilentlyContinue)
if ($CheckResult.GetType().Name -eq "ConfigurationAttribute") {
    $CheckResult = $CheckResult.Value
}

if ($CheckResult -ne $null)
{
    if ($CheckResult -ne "UseCookies") {
        $Result="Open"
        $Details += "SessionState cookieless set to $CheckResult "
    } else {
        $Comments+="SessionState cookieless set to $CheckResult "
    }
} else {
    $Result="Not_Reviewed"
    $Details+="Web config could not be queried. "
}

return @{Details=$Details;
            Comments=$Comments;
            Result=$Result}