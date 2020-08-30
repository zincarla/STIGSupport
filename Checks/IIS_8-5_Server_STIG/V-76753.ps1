Write-Verbose "V-100171"
$Result = "NotAFinding"
$Details = ""
$Comments = ""

$Settings = (New-Object -TypeName PSObject -Property @{Exists=(Test-Path "$($env:WinDir)\web\printers");FeatureEnabled=(Get-WindowsFeature -Name "Print-Internet").InstallState -eq "Installed"})

if ($Settings -ne $null)
{
    if ($Settings.Exists)
    {
        $Result = "Open"
        $Details = "Print directory exists. "
    }
    if ($Settings.FeatureEnabled)
    {
        $Result="Open"
        $Details += "Internet printing enabled. "
    }
} else {
    $Result="Not_Reviewed"
    $Details+="Printers could not be queried. "
}

return @{Details=$Details;
            Comments=$Comments;
            Result=$Result}