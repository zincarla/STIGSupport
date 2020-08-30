<#
.SYNOPSIS
    This checks for compliancy on V-30968

.PARAMETER BeginData
    Input data as returned by the begin.ps1 script for this stig. Maybe null if one is not provided.
#>
Param($BeginData)
Write-Verbose "V-30968"
$Details = ""
$Comments = ""
$Result = "Not_Reviewed"

#Perform necessary check
$Details = "There are files with loadFromRemoteSources. See comments for list."
$Found = $false;
$FullFileList = @()+$BeginData.EXEConfigs
$FullFileList += $BeginData.MachineConfigs
foreach($file in $FullFileList)
{
    if (Test-Path -Path $file) {
        $subresult = (Get-Content -Path $file -Raw) -match '(?i)<loadFromRemoteSources[\w\s="]*enabled\s*=\s*"true"(?-i)';#match <loadFromRemoteSources enabled="true"
        if ($subresult)
        {
            $found=$true
            $Comments += "`r`n"+$file
        }
    }
}
if (-not $Found)
{
    $Details = "No files were found with loadFromRemoteSources enabled."
    $result = "NotAFinding"
}
else
{
    $AppLockerEnforcement = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe" -Name "EnforcementMode" -ErrorAction SilentlyContinue).EnforcementMode
    if ($AppLockerEnforcement -ne $null -and $AppLockerEnforcement -eq 1) {
        $Result="NotAFinding"
        $Details += " However AppLocker rules are enabled."
    }
    else
    {
        $Result = "Open"
    }
}

#Return results
return @{Details=$Details;
        Comments=$Comments;
        Result=$Result}