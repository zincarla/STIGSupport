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
$IssueFound = $false
#Attach HKEY_USERS to powershell for use
New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS | Out-Null
#Grab root key of all users on machine
$usrs = Get-ChildItem "HKU:\";
foreach ($usr in $usrs)
{
    if (Test-Path ("HKU:\"+$usr.PSChildName+"\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing\"))
    {
        $regresult = Get-ItemProperty -Path ("HKU:\"+$usr.PSChildName+"\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing\") -Name "State" -ErrorAction SilentlyContinue
        if ($regresult -eq $null) {
            $IssueFound =$true
            $Comments +="`r`nNo State property for "+$usr.PSChildName
        }
        elseif ($regresult.State -eq 146432) #0x23C00
        {
            $Comments +="`r`nValue match on "+$usr.PSChildName
        }
    } else {
        $IssueFound
        $Comments += "`r`n$($usr.PSChildName) is missing the Software Publishing Key"
    }
}
if (-not $IssueFound)
{
    $Details = "All users have the correct setting set."
    $Result = "NotAFinding"
}
else
{
    $Result = "Open"
    $Details = "Issues found. See comments for list."
}

#Return results
return @{Details=$Details;
        Comments=$Comments;
        Result=$Result}