Write-Verbose "V-100189"
$Result = "NotAFinding"
$Details = ""
$Comments = ""

Import-Module WebAdministration;
$SettingArray = (Get-WebConfigurationProperty "system.webServer/httpProtocol" -Name "customHeaders" -ErrorAction SilentlyContinue)
$Settings = $SettingArray.Collection | Where-Object {$_.Name -eq "Strict-Transport-Security"}

if ($SettingArray -ne $null)
{
    if ($Settings -eq $null) {
        $Result = "Open"
        $Details = "'Strict-Transport-Security' is not set"
    } elseif ($Settings.Value -le 0) {
        $Result="Open"
        $Details = "'Strict-Transport-Security' is set to $($Settings.Value)"
    } else {
        $Comments = "'Strict-Transport-Security' is set to $($Settings.Value)"
    }
} else {
    $Result="Not_Reviewed"
    $Details+="Webconfig could not be queried. "
}

return @{Details=$Details;
            Comments=$Comments;
            Result=$Result}