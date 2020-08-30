# STIGSupport Documentation

There are two parts to this repository. First you have the StigSupport.psm1 powershell module. This contains all the code necessary for loading, and interacting with the CKL and XCCDF files. Second, there is a folder called Utility, which contains scripts that utilize the module to perform more complex operations. All the scripts assume your powershell session has the module imported. Ensure you import it first!

Several of the PowerShell functions require a checklist template. This is just an empty checklist file as saved from the DISA STIG viewer application or as exported from the included `Convert-ManualXCCDFToCKL` function. In order to work with a checklist, it needs to be loaded into memory first. Here is a basic example on how to get the result of a check from a checklist, set it to something else, then save the checklist.

```powershell
#Module is required for all CKL/XCCDF commands
Import-Module "C:\Example\Module\StigSupport.psm1"
#Load the checklist into memory
$CKLData = Import-StigCKL -Path "C:\CKLs\MyCKL.ckl"
#Write the current result of V-11111
Write-Host (Get-VulnCheckResult -CKLData $CKLData -VulnID "V-11111")
#Set the result of V-11111
Set-VulnCheckResult -CKLData $CKLData -VulnID "V-11111" -Details "Not set correctly" -Comments "Checked by script" -Result Open
#Save our changes back to the checklist
Export-StigCKL -CKLData $CKLData -Path "C:\CKLs\MyCKL.ckl"
```

This repository is split into three sections:

- Module: Module required for all scripts
- Utility: Misc. utilities to facilitate work with CKL files. View the readme under the utility folder for more information.
- Checks: Utility to automatically perform checks and fill out CKL files

For more information on each section, please review that section's readme file.

## Alternate Resources

[Microsoft PowerStig](https://github.com/Microsoft/PowerStig)
PowerShell modules that utilize DSC to enforce STIG compliance.

[Matt Preston's PowerStigScan](https://github.com/mapresto/PowerStigScan)
PowerShell module that utilizes PowerStig to scan resources using DSC.
