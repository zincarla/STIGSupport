Param($BeginData)
Write-Verbose "V-76783"

$Result = "NotAFinding"
$Details = ""
$Comments = ""

Import-Module WebAdministration

$StandardLogging = (Get-Item -PSPath "IIS:\Sites\$($BeginData.Site)").logFile.logExtFileFlags

$RequiredStandard = @("Date","Time","ClientIP", "UserName", "Method", "UriQuery", "HttpStatus", "Referer")

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

return @{Details=$Details;
            Comments=$Comments;
            Result=$Result}