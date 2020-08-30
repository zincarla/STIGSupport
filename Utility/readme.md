# Utilities

These scripts utilize the StigSupport module to perform more complex functions

## Convert-XCCDFtoCKL.ps1

Converts an XCCDF file (Output from SCAP) to a CKL file for further processing
Use the STIG viewer application to create a blank CKL file. That will be used for the TemplateCKLPath

```powershell
&"Convert-XCCDFtoCKL.ps1" -TemplateCKLPath "<Path to blank ckl>" -STIGName "<STIG name to filter XCCDF files to like U_Windows_2012_and_2012_R2_MS_V2R7_STIG>" -SaveDirectory "<A directory to save the results to>" [-XCCFPath "<Optional path to XCCF files directory. If not set, will auto set to %USERPROFILE%\SCC\RESULTS\SCAP The default directory>"]
```

## Report on Open checks

Saves a CSV file containing more detailed information on open checks for all CKL files located within a directory

```powershell
&"Export-OpenStigData.ps1" -CKLDirectory <Path to a folder containing all your CKL files> -SavePath <Path to a csv file to save>
```

## Set-NRtoOpen.ps1

This script will set any checks for a CKL file from Not_Reviewed to Open

```powershell
&"Set-NRtoOpen.ps1" -CKLPath <Path to the CKL file to edit>
```

## Export-MetricsReport.ps1

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

## Convert-ToNewCKLVersion.ps1

Attempts to convert a checklist in 1.x version to a compatible 2.6 version checklist. This has had limited testing and may not work, but is worth a shot.

```powershell
&"Convert-ToNewCKLVersion.ps1" -Source 'C:\CKLs\MyChecklist.ckl' -Destination 'C:\CKLs\UpgradedMyChecklist.ckl'
```

## ContinuousSTIG

This directory contains a set of scripts that facilitate an automatic review of CKL files. When used, this should automatically run SCAP scans based on targets in pre-existing CKL files, merge the old CKLs with update CKLs and then merge the SCAP results into those. The intended effect is that this takes care of most of the work in maintaining an up-to-date CKL repository. More documentation in the folder.
