Param($BeginData)
Write-Verbose "V-100219"

$Result = "NotAFinding"
$Details = ""
$Comments = ""

Import-Module WebAdministration;
$IsEnabled = (Get-WebConfigurationProperty "system.webServer/security/authentication/anonymousAuthentication" -name enabled -PSPath "IIS:\Sites\$($BeginData.Site)").Value
$UserName = (Get-WebConfigurationProperty "system.webServer/security/authentication/anonymousAuthentication" -name userName -PSPath "IIS:\Sites\$($BeginData.Site)").Value

if ($IsEnabled -ne $null)
{
    $Details+="Anonymous access enabled: "+$IsEnabled.ToString()+"`r`n"
    if ($UserName -eq "")
    {
        $Details+="Account in use is `"AppPool`"`r`n"
    } else {
        $Details+="Account in use is `""+$UserName+"`"`r`n"
    }
    if ($IsEnabled) {
        $Result="Not_Reviewed"
        $Details += "Please check sensitive groups for the above username"
    }
    #TODO: Maybe make this more automated, but it is a big check
} else {
    $Result="Not_Reviewed"
    $Details+="Web config could not be queried. "
}

return @{Details=$Details;
            Comments=$Comments;
            Result=$Result}
