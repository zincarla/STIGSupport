<#
.SYNOPSIS
    This checks for compliancy on V-30972

.PARAMETER BeginData
    Input data as returned by the begin.ps1 script for this stig. Maybe null if one is not provided.
#>
Param($BeginData)
Write-Verbose "V-30972"
$Details = ""
$Comments = ""
$Result = "Not_Reviewed"

#Perform necessary check
$Details = "The following files have defaultProxy setting and must manually be checked. For your convenience, the xml element is added to the comments."
$Found = $false;
$FullFileList = @()+$BeginData.EXEConfigs
$FullFileList += $BeginData.MachineConfigs
foreach($file in $FullFileList)
{
    if (Test-Path -Path $file){
        $subresult = (Get-Content -Path $file -Raw) -match '(?i)<\s*defaultProxy(?-i)';#match <defaultProxy. Too complex for further matching. Manual check required
        if ($subresult)
        {
            $found=$true
            $Comments += "`r`n"+$file
            $Comments += "`r`n"+([XML](Get-Content $file)).configuration.'system.net'.defaultProxy.OuterXml.ToString()
            $Comments += "`r`n"
        }
    }
}
if (-not $Found)
{
    $Details = "No files were found with defaultProxy node."
    $Result = "NotAFinding"
}

#Return results
return @{Details=$Details;
        Comments=$Comments;
        Result=$Result}