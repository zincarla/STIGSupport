<#
.SYNOPSIS
    This checks for compliancy on V-30926

.PARAMETER BeginData
    Input data as returned by the begin.ps1 script for this stig. Maybe null if one is not provided.
#>
Param($BeginData)
Write-Verbose "V-30926"
$Details = ""
$Comments = ""
$Result = "Not_Reviewed"

#Perform necessary check
$Details = "There are files with FIPS turned off. See comments for a list."
$Found = $false;
$FullFileList = @()+$BeginData.EXEConfigs
$FullFileList += $BeginData.MachineConfigs
foreach($file in $FullFileList)
{
    $subresult = (Get-Content $file) -match '(?i)<enforceFIPSPolicy[\w\s="]*enabled\s*=\s*"false"(?-i)';#match <enforceFIPSPolicy enabled="false"
    if ($subresult)
    {
        $Comments+="`r`n"+$File
        $Found = $true;
    }
}
if (-not $Found)
{
    $Details = "No files were found with an explicitly disabled FIPSPolicy."
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