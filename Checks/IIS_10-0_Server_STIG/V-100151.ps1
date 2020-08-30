Write-Verbose "V-100151"
$Result = "NotAFinding"
$Details = ""
$Comments = ""

Import-Module WebAdministration;
$Settings = (New-Object -TypeName PSObject -Property @{Browse=(Get-WebConfigurationProperty "//directoryBrowse" -Name "enabled")})
if ($Settings.Browse.GetType().Name -eq "ConfigurationAttribute") {
    $Settings.Browse = $Settings.Browse.Value
}

if ($Settings -ne $null)
{
    if ($Settings.Browse)
    {
        $Result="Open"
        $Details = "Browse enabled is set to $($Settings.Browse)"
    }
    else
    {
        $Details = "Browse enabled is set to $($Settings.Browse)"
    }
} else {
    $Result="Not_Reviewed"
    $Details+="Web config properties could not be queried. "
}

return @{Details=$Details;
            Comments=$Comments;
            Result=$Result}