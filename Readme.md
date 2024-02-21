# STIGCKLBSupport Documentation

There are two parts to this repository. First you have the Module folder containing StigCKLBSupport.psm1 and StigXCCDFSupport.psm1 powershell modules. These contain the code necessary for loading, and interacting with the CKLB files and XCCDF files. Second, there is a folder called Utility, which contains scripts that utilize the module to perform more complex operations. 

Most of these functions require a checklist template. This is just an empty checklist file as saved from the DISA STIG viewer application. In order to work with a checklist, it needs to be loaded into memory first with `Import-StigCKLBFile`

## V3 upgrade status

This repository is an updated project to support the new V3/JSON formatted CKLB files.

There are several changes to be aware of compared to the older module. All functions have been renamed to some form of `Verb-StigCKLB****` for functions in `StigCKLBSupport.psm1` and `Verb-StigXCCDF****` for functions in the `StigXCCDFSupport.psm1` module. This should allow importing the old and new modules together without conflict and makes the module more cohesive and hopefully predictable. Several functions that were involved in getting STIG Rule/Vuln attributes have all been merged under `Get-StigCKLBRuleInfo`. This won't work as a drop-in replacement for the old module due to all these changes and any relying scripts will also need work to function with this module.

## Example flow

Here is a basic example on how to get the result of a check from a checklist, set it to something else, then save the checklist.

```powershell
#Module is required for all CKLB commands
Import-Module "C:\Example\Module\StigCKLBSupport.psm1"
#Load the checklist into memory
$CKLBData = Import-StigCKLBFile -Path "C:\CKLBs\MyCKL.cklb"
#Write the current result of V-11111
Write-Host (Get-StigCKLBRuleInfo -CKLBData $CKLBData -VulnID "V-11111")
#Set the result of V-11111
Set-StigCKLBRuleFinding -CKLBData $CKLBData -VulnID "V-11111" -FindingDetails "Not set correctly" -Comments "Checked by script" -Result open
#Save our changes back to the checklist
Export-StigCKLBFile -CKLBData $CKLBData -Path "C:\CKLBs\MyCKL.cklb"
```

## Repository structure

This repository is split into two sections:

- Module: Module required for all scripts
- Utility: Misc. utilities to facilitate work with CKLB files.

For more information on each section, please review that section's readme file.

## Alternate Resources

[Microsoft PowerStig](https://github.com/Microsoft/PowerStig)
PowerShell modules that utilize DSC to enforce STIG compliance.

[Matt Preston's PowerStigScan](https://github.com/mapresto/PowerStigScan)
PowerShell module that utilizes PowerStig to scan resources using DSC.
