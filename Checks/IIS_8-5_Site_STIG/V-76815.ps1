Param($BeginData)
Write-Verbose "V-100225"

$Result = "NotAFinding"
$Details = ""
$Comments = ""

Import-Module WebAdministration;
$CheckResult = [System.Environment]::ExpandEnvironmentVariables((Get-Item -PSPath "IIS:\Sites\$($BeginData.Site)").PhysicalPath)

if ($CheckResult -ne $null)
{
    $Details+=$CheckResult
    if ($CheckResult.ToLower()[0] -eq $Env:windir.ToLower()[0]) {
        $Result="Open"
    }
} else {
    $Result="Not_Reviewed"
    $Details+="Web config could not be queried. "
}

return @{Details=$Details;
            Comments=$Comments;
            Result=$Result}