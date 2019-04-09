<#
.SYNOPSIS
    This checks for compliancy on V-7061

.PARAMETER BeginData
    Input data as returned by the begin.ps1 script for this stig. Maybe null if one is not provided.
#>
Write-Verbose "V-7061"

#Perform necessary check
$Details = "The following matches were found:"
$Comments = ""
$Result = "NotAFinding"
$Found = $false
foreach ($usr in $usrs)
{
    if (Test-Path ("HKU:\"+$usr.PSChildName+"\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing\"))
    {
        try
        {
            $regresult = ( Get-ItemProperty -Path ("HKU:\"+$usr.PSChildName+"\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing\") -Name "State" -ErrorAction SilentlyContinue).State;
            if ($regresult -band 160 -ne 0)#160 = Bits 6 and 8
            {
                $Found= $true;
                $Details +="`r`nBit match on "+$usr.PSChildName
            }
        } catch{}
    }
}
if (-not $Found)
{
    $Details = "No users were found with the incorrect bits set."
    $Result = "NotAFinding"
}
else
{
    $Result = "Open"
}

#Return results
return @{Details=$Details;
        Comments=$Comments;
        Result=$Result}