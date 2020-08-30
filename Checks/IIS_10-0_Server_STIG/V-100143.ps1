Write-Verbose "V-100143"
$Result = "NotAFinding"
$Details = ""
$Comments = ""

Import-Module WebAdministration;
$Settings = Get-WebConfigurationProperty "//sessionState" -Name "cookieless"
if ($Settings.GetType().Name -eq "ConfigurationAttribute") {
    $Settings = $Settings.Value
}

if ($Settings -ne $null)
{
    $Details = "cookieless is set to $Settings"

    if ($Settings -ne "UseCookies")
    {
        $Result="Open"
    }
} else {
    $Result="Not_Reviewed"
    $Details+="Web config properties could not be queried. "
}

return @{Details=$Details;
            Comments=$Comments;
            Result=$Result}