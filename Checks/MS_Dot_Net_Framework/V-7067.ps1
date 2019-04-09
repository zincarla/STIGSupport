<#
.SYNOPSIS
    This checks for compliancy on V-7067

.PARAMETER BeginData
    Input data as returned by the begin.ps1 script for this stig. Maybe null if one is not provided.
#>
Write-Verbose "V-7067"
$Details = ""
$Comments = ""
$Result = "Not_Reviewed"

#Perform necessary check
$Data = &("C:\Windows\Microsoft.NET\Framework64\v4.0.30319\caspol.exe") -all -lg
$Details = "Manual check required. See comments for output of caspol.exe"
$Comments = $Data | Out-String


#Return results
return @{Details=$Details;
        Comments=$Comments;
        Result=$Result}