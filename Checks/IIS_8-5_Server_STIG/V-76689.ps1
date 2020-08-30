Write-Verbose "V-100113"
$Result = "NotAFinding"
$Details = ""
$Comments = ""

Import-Module WebAdministration

$StandardLogging = (Get-Item -PSPath "IIS:\").siteDefaults.logFile.logExtFileFlags
$CustomLogging = (Get-Item -PSPath "IIS:\").siteDefaults.logFile.customFields.Collection

$RequiredStandard = @("UserName", "UserAgent", "Referer")
$RequiredCustom = @(
        @{SourceType="RequestHeader";SourceName="Authorization"},
        @{SourceType="ResponseHeader";SourceName="Content-Type"}
    )

if ($StandardLogging -ne $null -or $CustomLogging -ne $null)
{
    $StandardLogging = $StandardLogging.Split(",")
    foreach ($Item in $RequiredStandard)
    {
        if (-not $StandardLogging.Contains($Item))
        {
            $Result="Open"
            $Details+="Missing standard logging field $Item. "
        } else {
            $Comments+="Found standard logging field $Item. "

        }
    }

    foreach ($Entry in $RequiredCustom)
    {
        $Res = @()+@($CustomLogging | Where-Object -FilterScript {$_.sourceType -eq $Entry.SourceType -and $_.sourceName -eq $Entry.SourceName })
        if ($Res.Length -le 0){
            $Result="Open"
            $Details+="Missing $($Entry.SourceType)\$($Entry.SourceName). "
        } else {
            $Comments+="Found $($Entry.SourceType)\$($Entry.SourceName). "
        }
    }
} else {
    $Result="Not_Reviewed"
    $Details+="Logging fields not found by tool. Manual check required. "
}

return @{Details=$Details;
            Comments=$Comments;
            Result=$Result}