<#
.SYNOPSIS
    This checks for compliancy on V-31026

.PARAMETER BeginData
    Input data as returned by the begin.ps1 script for this stig. Maybe null if one is not provided.
#>
Param($BeginData)
Write-Verbose "V-31026"
$Details = ""
$Comments = ""
$Result = "Not_Reviewed"

#Perform necessary check
$Details = "There are files that have etwEnable set to false. See comments for list."
$Found = $false;
$FullFileList = @()+$BeginData.EXEConfigs
$FullFileList += $BeginData.MachineConfigs
foreach($file in $files)
{
    $subresult = (Get-Content $file) -match '(?i)<\s*etwEnable[\w\s="]*enabled\s*=\s*"false"(?-i)'; #Check for <etwEnable enabled="false"
    if ($subresult)
    {
        $found=$true
        $Comments += "`r`n"+$file
    }
}
if (-not $Found)
{
    $Details = "No files were found with etwEnable set to true."
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