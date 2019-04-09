<#
.SYNOPSIS
    This checks for compliancy on V-7070

.PARAMETER BeginData
    Input data as returned by the begin.ps1 script for this stig. Maybe null if one is not provided.
#>
Param($BeginData)
Write-Verbose "V-7070"
$Details = ""
$Comments = ""
$Result = "Not_Reviewed"

#Perform necessary check
$Details = "The check failed. See comments for a list of failed files "
$Found = $false
$FullFileList = @()+$BeginData.EXEConfigs
$FullFileList += $BeginData.MachineConfigs
foreach($file in $FullFileList)
{
    $Content = (Get-Content $file)
    $subresult = $Content -match '(?i)typefilterlevel\s*=\s*"full"(?-i)';#match typefilterleve ="full"
    $subresult2 = $Content -match '(?i)<\s*channel[\w\s="]*ref\s*=\s*"http\s?(server)?"(?-i)';#match <channel ref="http server"
    $subresult3 = $Content -match '(?i)<\s*channel[\w\s="]*port\s*=\s*"443"[\w\s="]*ref\s*=\s*"http\s?(server)?"(?-i)';#match <channel port="443" ref="http server"
    $subresult4 = $Content -match '(?i)<\s*channel[\w\s="]*ref\s*=\s*"http\s?(server)?"[\w\s="]*port\s*=\s*"443"(?-i)';#match <channel ref="http server" port="443"

    if ($subresult -and $subresult2 -and -not ($subresult3 -or $subresult4))
    {
        $found = $true;
        $Comments += "`r`n"+$file.FullName
    }
}
if (-not $Found)
{
    $Details = "No files were found with the typefilterlevel set with incorrect channel settings."
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