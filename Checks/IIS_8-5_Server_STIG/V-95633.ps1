Write-Verbose "V-100187"
$Result = "NotAFinding"
$Details = ""
$Comments = ""

Import-Module WebAdministration;
$Settings = (Get-WebConfigurationProperty "/system.applicationHost/sites" -Name "siteDefaults" -ErrorAction SilentlyContinue).limits.maxConnections

if ($Settings -ne $null)
{
    if ($Settings -eq 0)
    {
        $Result="Open"
        $Details = "maxConnections is set to $Settings"
    } else {
        $Comments = "maxConnections is set to $Settings"
    }
} else {
    $Result="Not_Reviewed"
    $Details+="Webconfig could not be queried. "
}

return @{Details=$Details;
            Comments=$Comments;
            Result=$Result}