<#
.SYNOPSIS
    This checks for compliancy on V-####

.PARAMETER BeginData
    Input data as returned by the begin.ps1 script for this stig. Maybe null if one is not provided.
#>
Param($BeginData)
Write-Verbose "V-####"
$Details = ""
$Comments = ""
$Result = "Not_Reviewed"

#Perform necessary check

#Return results
return @{Details=$Details;
        Comments=$Comments;
        Result=$Result}