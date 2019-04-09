<#
.SYNOPSIS
    This checks for compliancy on V-30937

.PARAMETER BeginData
    Input data as returned by the begin.ps1 script for this stig. Maybe null if one is not provided.
#>
Param($BeginData)
Write-Verbose "V-30937"
$Details = ""
$Comments = ""
$Result = "Not_Reviewed"

#Perform necessary check
$Details = "There are files with legacy security. See comments for list."
$Found = $false;
$FullFileList = @()+$BeginData.EXEConfigs
$FullFileList += $BeginData.MachineConfigs
foreach($file in $FullFileList)
{
    $subresult = (Get-Content $file) -match '(?i)NetFx40_LegacySecurityPolicy\s*enabled\s*=\s*"true"(?-i)';#match NetFx40_LegacySecurityPolicy enabled="true"
    if ($subresult)
    {
        $found=$true
        $Comments += "`r`n"+$file
    }
}
if (-not $Found)
{
    $Details = "No files were found with legacy security enabled."
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