Write-Verbose "V-100111"
$Result = "NotAFinding"
$Details = ""
$Comments = ""

Import-Module WebAdministration
$Logging = (Get-Item -PSPath "IIS:\").siteDefaults.logFile.customFields

$Required = @(@{SourceType="RequestHeader";SourceName="Connection"},
            @{SourceType="RequestHeader";SourceName="Warning"}
)

if ($Logging -ne $null)
{
    foreach ($Entry in $Required)
    {
        $Res = @()+@($Logging.Collection | Where-Object -FilterScript {$_.sourceType -eq $Entry.SourceType -and $_.sourceName -eq $Entry.SourceName })
        if ($Res.Length -le 0){
            $Result="Open"
            $Details+="Missing $($Entry.SourceType)\$($Entry.SourceName). "
        } else {
            $Details+="Found $($Entry.SourceType)\$($Entry.SourceName). "
        }
    }
} else {
    $Result="Not_Reviewed"
    $Details+="Logging fields not found by tool. Manual check required. "
}

return @{Details=$Details;
            Comments=$Comments;
            Result=$Result}