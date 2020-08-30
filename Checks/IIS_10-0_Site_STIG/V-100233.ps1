Param($BeginData)
Write-Verbose "V-100233"

$Result = "NotAFinding"
$Details = ""
$Comments = ""

Import-Module WebAdministration;
$CheckResult = (Get-WebConfigurationProperty "system.webServer/security/requestFiltering" -name allowHighBitCharacters -PSPath "IIS:\Sites\$($BeginData.Site)").Value

if ($CheckResult -ne $null)
{
    $Details+=$CheckResult.ToString()
    if ($CheckResult -ne $false) {
        $Result="Open"
    }
} else {
    $Result="Not_Reviewed"
    $Details+="Web config could not be queried. "
}

return @{Details=$Details;
            Comments=$Comments;
            Result=$Result}