Param($BeginData)
Write-Verbose "V-100259"

$Result = "NotAFinding"
$Details = ""
$Comments = ""

Import-Module WebAdministration;
$Settings = (New-Object -TypeName PSObject -Property @{SecureSession=(Get-WebConfigurationProperty "/system.webServer/asp" -Name "session" -PSPath "IIS:\Sites\$($BeginData.Site)").keepSessionIdSecure})

if ($Settings -ne $null)
{
    if (-not $Settings.SecureSession)
    {
        $Result="Open"
        $Details = "keepSessionIdSecure is set to $($Settings.SecureSession.ToString())"
    } else {
        $Comments = "keepSessionIdSecure is set to $($Settings.SecureSession.ToString())"
    }
} else {
    $Result="Not_Reviewed"
    $Details+="Web config could not be queried. "
}

return @{Details=$Details;
            Comments=$Comments;
            Result=$Result}