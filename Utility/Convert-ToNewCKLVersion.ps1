<#
.SYNOPSIS
    Attempts to convert a checklist in 1.x version to a compatible 2.6 version checklist

.DESCRIPTION
    Attempts to convert a checklist in 1.x version to a compatible 2.6 version checklist

.PARAMETER Source
    Full path to the CKL file to convert

.PARAMETER Destination
    Full path to the save location for the upgraded ckl
  
.EXAMPLE
    "Convert-ToNewCKLVersion.ps1" -Source 'C:\CKLs\MyChecklist.ckl' -Destination 'C:\CKLs\UpgradedMyChecklist.ckl'
#>
Param($Source, $Destination)
$Content = Get-Content -Path $Source -Raw -Encoding UTF8
$Content = $Content.Replace("<STIG_INFO>","<STIGS><iSTIG><STIG_INFO>").Replace("</CHECKLIST>","</iSTIG></STIGS></CHECKLIST>")
$Content = $Content -replace "<SV_VERSION>DISA STIG Viewer : .*</SV_VERSION>",""
$Content | Out-File $Destination -Encoding utf8