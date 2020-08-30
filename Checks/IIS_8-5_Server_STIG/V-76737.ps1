Write-Verbose "V-100155"
$Result = "NotAFinding"
$Details = ""
$Comments = ""

Import-Module WebAdministration;
$Settings = (New-Object -TypeName PSObject -Property @{ErrorMode=(Get-WebConfigurationProperty "//httpErrors" -Name "errorMode")})

if ($Settings -ne $null)
{
    $Details = "ErrorMode is set to $($Settings.ErrorMode)"

    if ($Settings.ErrorMode -ne "DetailedLocalOnly")
    {
        $Result="Open"
    }

} else {
    $Result="Not_Reviewed"
    $Details+="Webconfig could not be queried. "
}

return @{Details=$Details;
            Comments=$Comments;
            Result=$Result}