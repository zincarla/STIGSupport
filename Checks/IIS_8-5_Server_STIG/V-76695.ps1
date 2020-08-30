Write-Verbose "V-100115"
$Result = "NotAFinding"
$Details = ""
$Comments = ""

Import-Module WebAdministration
$LogDir =(Get-WebConfigurationProperty "//centralw3clogfile" -Name "directory")
if ($LogDir.GetType().Name -eq "ConfigurationAttribute") {
    $LogDir = $LogDir.Value
}

if ($LogDir -ne $null)
{
    try {
        $ACL = (Get-ACL -Path ([System.Environment]::ExpandEnvironmentVariables($LogDir)) -ErrorAction Stop).Access
        #ACLCheck
        $AllowedArray=@("BUILTIN\Administrators","NT AUTHORITY\SYSTEM")
        foreach ($AC in $ACL)
        {
            if ($AC.AccessControlType -eq "Allow" -and -not $AllowedArray.Contains($AC.IdentityReference.Value))
            {
                $Result="Open"
                $Details+=$AC.IdentityReference.ToString()+" has ("+$AC.FileSystemRights.ToString()+") which is against STIG. "
            }
        }
        $Comments="Log directory is $([System.Environment]::ExpandEnvironmentVariables($LogDir))"
    } catch {
        $Result="Not_Reviewed"
        $Details+="Error checking log directory permissions. "
    }
} else {
    $Result="Not_Reviewed"
    $Details+="Logging directory not found. "
}

return @{Details=$Details;
            Comments=$Comments;
            Result=$Result}