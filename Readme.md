# STIGSupport Documentation

There are two parts to this repository. First you have the StigSupport.psm1 powershell module. This contains all the code necessary for loading, and interacting with the CKL and XCCDF files. Second, there is a folder called Utility, which contains scripts that utilize the module to perform more complex operations. All the scripts assume your powershell session has the module imported. Ensure you import it first!

Several of the PowerShell functions require a checklist template. This is just an empty checklist file as saved from the DISA STIG viewer application. In order to work with a checklist, it needs to be loaded into memory first. Here is a basic example on how to get the result of a check from a checklist, set it to something else, then save the checklist.

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

This repository is split into two folders, these folder follow the following structure:

- Module: Module required for all scripts
- Utility: Misc. utilities to facilitate work with CKL files.

## Utilities

These scripts utilize the StigSupport module to perform more complex functions

### Convert-XCCDFtoCKL.ps1

Converts an XCCDF file (Output from SCAP) to a CKL file for further processing
Use the STIG viewer application to create a blank CKL file. That will be used for the TemplateCKLPath

```powershell
&"Convert-XCCDFtoCKL.ps1" -TemplateCKLPath "<Path to blank ckl>" -STIGName "<STIG name to filter XCCDF files to like U_Windows_2012_and_2012_R2_MS_V2R7_STIG>" -SaveDirectory "<A directory to save the results to>" [-XCCFPath "<Optional path to XCCF files directory. If not set, will auto set to %USERPROFILE%\SCC\RESULTS\SCAP The default directory>"]
```

### Report on Open checks

Saves a CSV file containing more detailed information on open checks for all CKL files located within a directory

```powershell
&"Export-OpenStigData.ps1" -CKLDirectory <Path to a folder containing all your CKL files> -SavePath <Path to a csv file to save>
```

### Set-NRtoOpen.ps1

This script will set any checks for a CKL file from Not_Reviewed to Open

```powershell
&"Set-NRtoOpen.ps1" -CKLPath <Path to the CKL file to edit>
```

### Export-MetricsReport.ps1

This script will output several CSV files containing general metrics on stig progress. Note that the directory tree that your CKL files are in, must be in a certain format!

```powershell
&"Export-MetricsReport.ps1" -CKLDirectoryPath <Path to parent of CKL folders> -SavePath <Path to save CSV reports>
```

The Directory Tree should follow something like this example:

```text
C:\Parent
    |-IIS
    |  |-IIS Server 1.ckl
    |  |-IIS Server 2.ckl
    |
    |-DNS
       |-DNS Server 1.ckl
```

The command to run the script against the directory tree above would look like the following.

```powershell
&"Export-MetricsReport.ps1" -CKLDirectoryPath "C:\Parent" -SavePath "C:\Reports"
```

And it would output two CSV files, one named "IIS.csv" and the other named "DNS.csv". The CSVs themselves would follow this format

Open | Total | NotAFinding | UniqueTotal | NotApplicable | Category | NotReviewed
--- | --- | --- | --- | --- | --- | ---
50 | 200 | 50 | 50 | 200 | Cat1 | 50
0 | 0 | 0 | 0 | 0 | Cat3 | 0
25 | 200 | 75 | 200 | 25 | Cat2 | 75

### Export-POAMData.ps1

Script will run through a target directory and build a collection of CKL files. From there it will parse them and find all checks that are set to Open or Not Reviewed and add each to an object. End result is a CSV file that can be used to copy and paste bulk POA&M data into a provided template.

```powershell
&"Export-POAMData.ps1" -CKLDirectory <path to desired CKLs> -SavePath <Desired path and filename.csv>
```

### Convert-ToNewCKLVersion.ps1

Attempts to convert a checklist in 1.x version to a compatible 2.6 version checklist. This has had limited testing and may not work, but is worth a shot.

```powershell
&"Convert-ToNewCKLVersion.ps1" -Source 'C:\CKLs\MyChecklist.ckl' -Destination 'C:\CKLs\UpgradedMyChecklist.ckl'
```

### ContinuousSTIG.ps1

This script will compare a directory containing CKL files with the latest STIG library and email a report on CKL files and checks that need to be re-evaluated. The intent is to have this run on a monthly schedule to ensure awareness of, and compliance with, STIGs as they are updated. As a brief overview, this script will:

- Prepare a staging directory
- Attempt to download the latest STIG library (NON-FOUO)
- Extract it to the staging directory and all STIGs within it
- Loop through the newly downloaded STIGs, and the user's CKL files comparing them
- Email any noted differences to the specified users

```powershell
&"ContinuousSTIG.ps1" -CKLDirectory "\\MyShare\MyChecklists" -EmailServer "MySMTPServer" -EmailRecipients @("myadmin@mydomain.com", "mytest@test.com") -EmailFrom "STIGReport@mydomain.com"
```
