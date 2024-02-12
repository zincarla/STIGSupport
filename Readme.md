# STIGCLKBSupport Documentation

There are two parts to this repository. First you have the StigCKLBSupport.psm1 powershell module. This contains all the code necessary for loading, and interacting with the CKLB files. Second, there is a folder called Utility, which contains scripts that utilize the module to perform more complex operations. All the scripts assume your powershell session has the module imported. Ensure you import it first!

The repository is not at parity with the old V2 module as far as XCCDF, CCI, or additional scripts goes, however the core module *should* be functional for CKLB operations.

Several of the PowerShell functions require a checklist template. This is just an empty checklist file as saved from the DISA STIG viewer application. In order to work with a checklist, it needs to be loaded into memory first. Here is a basic example on how to get the result of a check from a checklist, set it to something else, then save the checklist.

```powershell
#Module is required for all CKL/XCCDF commands
Import-Module "C:\Example\Module\StigCKLBSupport.psm1"
#Load the checklist into memory
$CKLData = Import-StigCKLBFile -Path "C:\CKLBs\MyCKL.cklb"
#Write the current result of V-11111
Write-Host (Get-StigCKLBRuleInfo -CKLBData $CKLBData -VulnID "V-11111")
#Set the result of V-11111
Set-StigCKLBRuleFinding -CKLBData $CKLBData -VulnID "V-11111" -FindingDetails "Not set correctly" -Comments "Checked by script" -Result open
#Save our changes back to the checklist
Export-StigCKLBFile -CKLBData $CKLBData -Path "C:\CKLBs\MyCKL.cklb"
```

This repository is split into two sections:

- Module: Module required for all scripts
- Utility: Misc. utilities to facilitate work with CKLB files.

For more information on each section, please review that section's readme file.

## Alternate Resources

[Microsoft PowerStig](https://github.com/Microsoft/PowerStig)
PowerShell modules that utilize DSC to enforce STIG compliance.

[Matt Preston's PowerStigScan](https://github.com/mapresto/PowerStigScan)
PowerShell module that utilizes PowerStig to scan resources using DSC.
