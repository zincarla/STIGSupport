Write-Verbose "V-100127"
$Result = "NotAFinding"
$Details = ""
$Comments = ""

$Users = @()
$server = $env:COMPUTERNAME
$localgroup = "Users"
$Group= [ADSI]"WinNT://$Server/$LocalGroup,group"
$members = $Group.psbase.Invoke("Members")
$members | ForEach-Object { $Users+=$_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null) }

$Exclusions = @("INTERACTIVE", "Authenticated Users", "Domain Users")

if ($Users -ne $null -and $Users.Length -gt 0)
{
    foreach ($U in $Users)
    {
        if (-not $Exclusions.Contains($U))
        {
            $Result = "Not_Reviewed"
            $Details += "$U`r`n"
        }
    }
    if ($Result -eq "Not_Reviewed")
    {
        $Details="Check did not pass filter, however this does not mean this stig item is open, please manually verify the following accounts against the STIG `r`n $Details"
    }
} else {
    $Result="Not_Reviewed"
    $Details+="Users could not be loaded. "
}

return @{Details=$Details;
            Comments=$Comments;
            Result=$Result}