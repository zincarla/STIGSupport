Write-Verbose "V-100153"
$Result = "NotAFinding"
$Details = ""
$Comments = ""


Import-Module WebAdministration;
$Settings = (New-Object -TypeName PSObject -Property @{Exists=(Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Control\ContentIndex\Catalogs")})

if ($Settings.Exists -ne $null)
{
    if (-not $Settings.Exists)
    {
        $Result="Not_Applicable"
        $Details = "Index key does not exist "
    }
    else
    {
        $Result="Not_Reviewed"
        $Details = "Manual check required. " #TODO: It should be possible to automate this fully, but this is a good 90% check
    }

} else {
    $Result="Not_Reviewed"
    $Details+="Index registry could not be queried. "
}

return @{Details=$Details;
            Comments=$Comments;
            Result=$Result}