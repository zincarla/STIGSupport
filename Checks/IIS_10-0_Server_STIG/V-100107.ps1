Write-Verbose "V-100107"
$Result = "NotAFinding"
$Details = ""
$Comments = ""

Import-Module WebAdministration
$Logging = (Get-Item -PSPath "IIS:\").siteDefaults.logFile.logTargetW3C

if ($Logging -ne "" -and $Logging -ne $null)
{
    $Required = @("File","ETW")
    $Logging = $Logging.Split(",")
    foreach ($Item in $Required)
    {
        if (-not $Logging.Contains($Item))
        {
            $Result = "Open"
            $Details+=$Item+" is missing. "
        }else{
            $Details+=$Item+" found. "
        }
    }
} else {
    $Result="Not_Reviewed"
    $Details+="Logging targets not found by tool. Manual check required. "
}

return @{Details=$Details;
            Comments=$Comments;
            Result=$Result}