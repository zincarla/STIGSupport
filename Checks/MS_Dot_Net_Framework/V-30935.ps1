<#
.SYNOPSIS
    This checks for compliancy on V-30935

.PARAMETER BeginData
    Input data as returned by the begin.ps1 script for this stig. Maybe null if one is not provided.
#>
Param($BeginData)
Write-Verbose "V-30935"
$Details = ""
$Comments = ""
$Result = "Not_Reviewed"

#Perform necessary check
$subresult = Test-Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\";
if ($subresult)
{    
    $subresult = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\").AllowStrongNameBypass;
    if ($subresult -eq 1 -or $subresult -eq $null)
    {
        $Details = "AllowStrongNameBypass either does not exist or is set to 1"
        $Result="Open"
    }
    else
    {
        $Details = "AllowStrongNameBypass exists and is set to $($subresult.ToString())"
        $Result = "NotAFinding"
    }
}
else
{
    $Details = "dot net not installed? HKLM:\SOFTWARE\Microsoft\.NETFramework\ does not exist"
    $Result = "NotAFinding"
}

#Return results
return @{Details=$Details;
        Comments=$Comments;
        Result=$Result}