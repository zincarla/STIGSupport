Param($BeginData)
Write-Verbose "V-100205"

$Result = "NotAFinding"
$Details = ""
$Comments = ""

Import-Module WebAdministration

$StandardLogging = (Get-Item -PSPath "IIS:\Sites\$($BeginData.Site)").logFile.logExtFileFlags
$CustomLogging = (Get-Item -PSPath "IIS:\Sites\$($BeginData.Site)").logFile.customFields.Collection

$RequiredStandard = @("UserName", "UserAgent", "Referer")
$RequiredCustom = @(
        @{SourceType="RequestHeader";SourceName="Authorization"},
        @{SourceType="ResponseHeader";SourceName="Content-Type"}
    )


if ($StandardLogging -ne $null) {
    $StandardLogging = $StandardLogging.Split(",")
    foreach ($Item in $RequiredStandard)
    {
        if (-not $StandardLogging.Contains($Item))
        {
            $Result="Open"
            $Details+="Missing standard logging field $Item. "
        } else {
            $Details+="Found standard logging field $Item. "

        }
    }
} else {
    $Result="Open"
    $Details+="Standard logging fields not set. "
}
if ($StandardLogging -ne $null) {
    foreach ($Entry in $RequiredCustom)
    {
        $Res = @()+@($CustomLogging | Where-Object -FilterScript {$_.sourceType -eq $Entry.SourceType -and $_.sourceName -eq $Entry.SourceName })
        if ($Res.Length -le 0){
            $Result="Open"
            $Details+="Missing $($Entry.SourceType)\$($Entry.SourceName). "
        } else {
            $Details+="Found $($Entry.SourceType)\$($Entry.SourceName). "
        }
    }
} else {
    $Result="Open"
    $Details+="Custom logging fields not set. "
}


return @{Details=$Details;
            Comments=$Comments;
            Result=$Result}