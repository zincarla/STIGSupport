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
$Result = "NotAFinding"

#Perform necessary check
$KeysToCheck = @("HKLM:\SOFTWARE\Microsoft\.NETFramework\", "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\")
foreach ($Key in $KeysToCheck) {
    $subresult = Test-Path $Key;
    if ($subresult)
    {    
        $subresult = (Get-ItemProperty -Path $Key -ErrorAction SilentlyContinue).AllowStrongNameBypass;
        if ($subresult -eq 1 -or $subresult -eq $null)
        {
            $Details += "AllowStrongNameBypass either does not exist or is set to '1' for $Key `r`n"
            $Result = "Open"
        }
        else
        {
            $Details += "AllowStrongNameBypass exists and is set to $($subresult.ToString()) for $Key `r`n"
        }
    }
    else
    {
        $Details = ".NET not installed? $Key does not exist `r`n"
        if ($Result -ne "Open") {
            $Result = "Not_Reviewed"
        }
    }
}
#Return results
return @{Details=$Details;
        Comments=$Comments;
        Result=$Result}