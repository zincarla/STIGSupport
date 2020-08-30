Write-Verbose "V-100183"
$Result = "NotAFinding"
$Details = ""
$Comments = ""

Import-Module WebAdministration;
$Settings = (New-Object -TypeName PSObject -Property @{CGI=(Get-WebConfigurationProperty "//isapiCgiRestriction" -Name "notListedCgisAllowed");
                                                      ISAPI=(Get-WebConfigurationProperty "//isapiCgiRestriction" -Name "notListedIsapisAllowed")})
if ($Settings.ISAPI.GetType().Name -eq "ConfigurationAttribute") {
    $Settings.ISAPI = $Settings.ISAPI.Value
}
if ($Settings.CGI.GetType().Name -eq "ConfigurationAttribute") {
    $Settings.CGI = $Settings.CGI.Value
}

if ($Settings -ne $null)
{
    if ($Settings.CGI)
    {
        $Result="Open"
        $Details += "'Allow unspecified CGI modules' Checked`r`n"
    } else {
        $Comments += "'Allow unspecified CGI modules' not checked`r`n"
    }

    if ($Settings.ISAPI)
    {
        $Result="Open"
        $Details += "'Allow unspecified ISAPI modules' Checked`r`n"
    } else {
        $Comments += "'Allow unspecified ISAPI modules' not checked`r`n"
    }

} else {
    $Result="Not_Reviewed"
    $Details+="Webconfig could not be queried. "
}

return @{Details=$Details;
            Comments=$Comments;
            Result=$Result}