Param($BeginData)
Write-Verbose "V-100223"

$Result = "NotAFinding"
$Details = ""
$Comments = ""


Import-Module WebAdministration;
$CheckResult = (Get-WebConfigurationProperty "/system.web/sessionState" -name mode -PSPath "IIS:\Sites\$($BeginData.Site)")


if ($CheckResult -ne $null)
{
    $Details+=$CheckResult
    if ($CheckResult -ne "InProc") {
        $Result="Open"
    }
} else {
    $Result="Not_Reviewed"
    $Details+="Web config could not be queried. "
}

return @{Details=$Details;
            Comments=$Comments;
            Result=$Result}