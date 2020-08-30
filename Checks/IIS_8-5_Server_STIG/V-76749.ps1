Write-Verbose "V-100167"
$Result = "NotAFinding"
$Details = ""
$Comments = ""


$Settings = (New-Object -TypeName PSObject -Property @{Exists=(Test-Path "$($env:WinDir)\System32\inetsrv\inetmgr.exe");Permissions=(Get-ACL -Path "$($env:WinDir)\System32\inetsrv\inetmgr.exe").Access})

$ExcludedFull = @("NT SERVICE\TrustedInstaller", "NT AUTHORITY\SYSTEM")
$CatchAll = @("ReadAndExecute", "Synchronize")
if ($Settings -ne $null)
{
    if (-not $Settings.Exists)
    {
        $Result = "Not_Reviewed"
        $Details = "inetmgr.exe not in expected directory. Check manually."
    }
    else
    {
        foreach ($AC in $Settings.Permissions)
        {
            if (-not $ExcludedFull.Contains($AC.IdentityReference.Value) -and $AC.AccessControlType -eq "Allow")
            {
                foreach ($A in $AC.FileSystemRights.ToString().Split(", ", [StringSplitOptions]::RemoveEmptyEntries))
                {
                    if (-not $CatchAll.Contains($A.ToString()))
                    {
                        $Result = "Open"
                        $Details+=">>>$($AC.IdentityReference.Value) has $($A.ToString())`n"
                    }
                    else
                    {
                        $Comments+="$($AC.IdentityReference.Value) has $($A.ToString())`n"
                    }
                }
            }
        }
    }
} else {
    $Result="Not_Reviewed"
    $Details+="Inetmgr could not be queried. "
}

return @{Details=$Details;
            Comments=$Comments;
            Result=$Result}