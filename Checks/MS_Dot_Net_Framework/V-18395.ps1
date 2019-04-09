<#
.SYNOPSIS
    This checks for compliancy on V-18395

.PARAMETER BeginData
    Input data as returned by the begin.ps1 script for this stig. Maybe null if one is not provided.
#>
Param($BeginData)
Write-Verbose "V-18395"
$Details = ""
$Comments = ""
$Result = "Not_Reviewed"

#Perform necessary check
$Versions = Get-ChildItem -Path ($ENV:SYSTEMROOT+"\Microsoft.NET") -Filter "mscorlib.dll" -Recurse | foreach -Process {$_.VersionInfo.ProductVersion} | Sort-Object | Select -Unique
$Details = "Unable to automate. Please check the comments section and verify the .Net versions installed are still supported. See http://support.microsoft.com/lifecycle/search/?sort=PN&alpha=.NET+Framework"
$Comments=".Net Versions Found:"
foreach ($Version in $Versions)
{
    $Comments += "`r`n"+$Version.ToString()
}

#Return results
return @{Details=$Details;
        Comments=$Comments;
        Result=$Result}