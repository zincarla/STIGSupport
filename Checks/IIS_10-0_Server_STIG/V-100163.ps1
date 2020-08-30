Write-Verbose "V-100163"
$Result = "NotAFinding"
$Details = ""
$Comments = ""


$Settings = (New-Object -TypeName PSObject -Property @{Exists=(Test-Path "$($env:SystemDrive)\inetpub");Permissions=(Get-ACL -Path "$($env:SystemDrive)\inetpub").Access})

$ExcludedFull = @("NT SERVICE\TrustedInstaller", "BUILTIN\Administrators", "NT AUTHORITY\SYSTEM")
$Other = @{"CREATOR OWNER"=@("268435456");"BUILTIN\Users" = @("268435456", "-1610612736", "ReadAndExecute", "Synchronize");}

$DomainCatchDomain="$env:USERDOMAIN\"
$DomainCatch = @("268435456", "ReadAndExecute", "Synchronize", "-1610612736")

if ($Settings -ne $null)
{
    if (-not $Settings.Exists)
    {
        $Result = "Not_Reviewed"
        $Details = "inetpub not in expected directory. Check manually."
    } else {
        foreach ($AC in $Settings.Permissions) {
            #If this is not the creater owner with correct permissions
            if (-not ($AC.IdentityReference.Value -eq "CREATOR OWNER" -and $AC.PropagationFlags -eq "InheritOnly")) {
                #And this is not an allowed full control user
                if (-not $ExcludedFull.Contains($AC.IdentityReference.Value) -and $AC.AccessControlType -eq "Allow") {
                    #Then check if they are in the other exlusion group with correct permissions
                    #Barring that, we check if it is a domain user/group that has the same permissions allowed for all users
                    if ($Other.ContainsKey($AC.IdentityReference.Value)) {
                        $Found = $false;
                        foreach ($A in $AC.FileSystemRights.ToString().Split(", ", [StringSplitOptions]::RemoveEmptyEntries)) {
                            if (-not $Other[$AC.IdentityReference.Value].Contains($A)) {
                                $Found=$true
                                $Result = "Open"
                                $Details+="$($AC.IdentityReference.Value) has $($A) when they shouldn't. "
                            }
                        }
                        if (-not $Found) {
                            $Comments+="$($AC.IdentityReference.Value) has $($AC.FileSystemRights.ToString()) as allowed. "
                        }
                    } elseif ($AC.IdentityReference.Value.StartsWith($DomainCatchDomain)) {
                        $Found = $false;
                        foreach ($A in $AC.FileSystemRights.ToString().Split(", ", [StringSplitOptions]::RemoveEmptyEntries)) {
                            if (-not $DomainCatch.Contains($A)) {
                                $Found=$true
                                $Result = "Open"
                                $Details+="$($AC.IdentityReference.Value) has $($A) when they shouldn't. "
                            }
                        }
                        if (-not $Found) {
                            $Comments+="$($AC.IdentityReference.Value) has $($AC.FileSystemRights.ToString()) as allowed. "
                        }
                    } else {
                        $Details+="$($AC.IdentityReference.Value) has access when they possibly shouldn't"
                        $Result = "Open"
                    }
                } else {
                    $Comments+="$($AC.IdentityReference.Value) was found with full admin as allowed. "  
                }
            } else {
                $Comments+="$($AC.IdentityReference.Value) was found with correct settings. "
            }
        }
    }
} else {
    $Result="Not_Reviewed"
    $Details+="Windows permissions could not be queried. "
}

return @{Details=$Details;
            Comments=$Comments;
            Result=$Result}