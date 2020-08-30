Write-Verbose "V-100185"
$Result = "NotAFinding"
$Details = ""
$Comments = ""

Import-Module WebAdministration;
$Users = @()
(Get-WebConfigurationProperty "/system.web/authorization" -Name "collection") | ForEach-Object -Process {$Users+=$_.roles+$_.users}

if ($Settings -ne $null)
{
    if ($Users.Length -gt 0)
    {
        foreach($Item in $Users)
        {
            if ($Item -ne "Administrators")
            {
                $Details+="$Item was found and is not allowed."
                $Result="Open"
            } else {
                $Comments += "$Item was found and is allowed."
            }
        }
    } else {
        $Comments += "No restricted entries`r`n"
    }
} else {
    $Result="Not_Reviewed"
    $Details+="Webconfig could not be queried. "
}

return @{Details=$Details;
            Comments=$Comments;
            Result=$Result}