Param($BeginData)
Write-Verbose "V-100261"

$Result = "NotAFinding"
$Details = ""
$Comments = ""

Import-Module WebAdministration;
$Settings = (New-Object -TypeName PSObject -Property @{Compression=(Get-WebConfigurationProperty "system.web/sessionState" -Name "compressionEnabled" -PSPath "IIS:\Sites\$($BeginData.Site)").Value;RequireSSL=(Get-WebConfigurationProperty "system.web/httpCookies" -Name "requireSSL" -PSPath "IIS:\Sites\$($BeginData.Site)").Value})

if ($Settings -ne $null)
{
    if ($Settings.Compression -ne $false -or $Settings.RequireSSL -ne $true)
    {
        $Result="Open"
    }
    $Details += "Secure Compression is set to $($Settings.Compression.ToString())`r`n"
    $Details += "Cookie RequireSSL is set to $($Settings.RequireSSL.ToString())`r`n"
} else {
    $Result="Not_Reviewed"
    $Details+="Web config could not be queried. "
}

return @{Details=$Details;
            Comments=$Comments;
            Result=$Result}