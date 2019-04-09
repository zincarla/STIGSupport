<#
.SYNOPSIS
    This checks for compliancy on V-32025

.PARAMETER BeginData
    Input data as returned by the begin.ps1 script for this stig. Maybe null if one is not provided.
#>
Param($BeginData)
Write-Verbose "V-32025"
$Details = ""
$Comments = ""
$Result = "Not_Reviewed"

#Perform necessary check
$Details = "There are files that do not have encryption and message integrity with typefilter full. See comments for list."
$Found = $false;
foreach($file in $files)
{
    $Content = (Get-Content $file)
    
    $result5 = $Content -match '(?i)<\s*channel[\w\s="]*secure\s*=\s*"false"(?-i)'; #Check for <channel secure="false"
    $result1 = $Content -match '(?i)typefilterlevel\s*=\s*"full"(?-i)'; #match typefilterlevel ="full"
    $result2 = $Content -match '(?i)<\s*channel[\w\s="]*ref\s*=\s*"tcp\s?(server)?"[\w\s="]*secure\s*=\s*"true"(?-i)'; #Check for <channel ref="tcp" secure="true"
    $result3 = $Content -match '(?i)<\s*channel[\w\s="]*secure\s*=\s*"true"[\w\s="]*ref\s*=\s*"tcp\s?(server)?"(?-i)'; #Check for <channel secure="true" ref="tcp" 
    $result4 = $Content -match '(?i)<\s*channel[\w\s="]*ref\s*=\s*"tcp\s?(server)?"(?-i)'; #Check for <channel ref="tcp"

    if ($result1 -and ($result5 -or ($result4 -and -not ($result3 -or $result2)))) #if anything is set to secure=false or if ref=tcp is detected but without a secure=true
    {
        $found=$true
        $Comments += "`r`n"+$file
    }
}
if (-not $Found)
{
    $Details = "No files were found with disabled encryption/integrity with typeFilter Full."
    $Result =  "NotAFinding"
}
else
{
    $Result = "Not_Reviewed"
}

#Return results
return @{Details=$Details;
        Comments=$Comments;
        Result=$Result}