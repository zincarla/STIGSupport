Write-Verbose "V-100145"
$Result = "NotAFinding"
$Details = ""
$Comments = ""

Import-Module WebAdministration;
$Settings = (New-Object -TypeName PSObject -Property @{CookieMode=(Get-WebConfigurationProperty "//sessionState" -Name "cookieless");TimeOut=(Get-WebConfigurationProperty "//sessionState" -Name "TimeOut").Value.TotalMinutes})
if ($Settings.CookieMode.GetType().Name -eq "ConfigurationAttribute") {
    $Settings.CookieMode = $Settings.CookieMode.Value
}

if ($Settings -ne $null)
{
    $Details = "cookieless is set to $($Settings.CookieMode)`r`nTimeOut set to $($Settings.TimeOut)"

    if ($Settings.CookieMode -ne "UseCookies" -or $Settings.TimeOut -gt 20)
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