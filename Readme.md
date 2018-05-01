# General Usage Information
There are two parts to this repository. First you have the StigSupport.psm1 powershell module. This contains all the code necessary for loading, and interacting with the CKL and XCCDF files. Second, there is a folder called Utility, which contains scripts that utilize the moduel to perform more complex operations. All the scripts assume your powershell session has the module imported. Ensure you import it first!

Several of the PowerShell functions require a checklist template. This is just an empty checklist file as saved from the DISA STIG viewer application. In order to work with a checklist, it needs to be loaded into memory first. Here is a basic example on how to get the result of a check from a checklist, set it to something else, then save the checklist.

```
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

## Folder Structure
- Module: Module required for all scripts
- Utility: Misc. utilities to facilitate work with CKL files.

## Utilities
### Convert-XCCDFtoCKL.ps1
Converts an XCCDF file (Output from SCAP) to a CKL file for further processing
Use the STIG viewer application to create a blank CKL file. That will be used for the TemplateCKLPath
```
&"Convert-XCCDFtoCKL.ps1" -TemplateCKLPath "<Path to blank ckl>" -STIGName "<STIG name to filter XCCDF files to like U_Windows_2012_and_2012_R2_MS_V2R7_STIG>" -SaveDirectory "<A direcotry to save the results to>" [-XCCFPath "<Optional path to XCCF files directory. If not set, will auto set to %USERPROFILE%\SCC\RESULTS\SCAP The default directory>"]
```

### Report on Open checks
Saves a CSV file containing more detailed information on open checks for all CKL files located within a directory
```
&"Export-OpenStigData.ps1" -CKLDirectory <Path to a folder containing all your CKL files> -SavePath <Path to a csv file to save>
```

### Set-NRtoOpen.ps1
This script will set any checks for a CKL file from Not_Reviewed to Open
```
&"Set-NRtoOpen.ps1" -CKLPath <Path to the CKL file to edit>
```

### Export-MetricsReport.ps1
This script will output several CSV files containing general metrics on stig progress. Note that the directory tree that your CKL files are in, must be in a certain format!
```
&"Export-MetricsReport.ps1" -CKLDirectoryPath <Path to parent of CKL folders> -SavePath <Path to save CSV reports>
```
#### Directory Tree Example
```
C:\Parent
    |-IIS
    |  |-IIS Server 1.ckl
    |  |-IIS Server 2.ckl
    |
    |-DNS
       |-DNS Server 1.ckl
```
The command to run the script against the directory tree above would look like the following.
```
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
```
&"Export-POAMData.ps1" -CKLDirectory <path to desired CKLs> -SavePath <Desired path and filename.csv>
```

### Convert-ToNewCKLVersion.ps1
Attempts to convert a checklist in 1.x version to a compatible 2.6 version checklist. This has had limited testing and may not work, but is worth a shot.
```
&"Convert-ToNewCKLVersion.ps1" -Source 'C:\CKLs\MyChecklist.ckl' -Destination 'C:\CKLs\UpgradedMyChecklist.ckl'
```

### ContinuousSTIG.ps1
This script will compare a directory containing CKL files with the latest STIG library and email a report on CKL files and checks that need to be re-evaluated. The intent is to have this run on a monthly schedule to ensure awareness of, and compliance with, STIGs as they are updated. As a brief overview, this script will:
* Prepare a staging directory
* Attempt to download the latest STIG library (NON-FOUO)
* Extract it to the staging directory and all STIGs within it
* Loop through the newly downloaded STIGs, and the user's CKL files comparing them
* Email any noted differences to the specified users
```
&"ContinuousSTIG.ps1" -CKLDirectory "\\MyShare\MyChecklists" -EmailServer "MySMTPServer" -EmailRecipients @("myadmin@mydomain.com", "mytest@test.com") -EmailFrom "STIGReport@mydomain.com"
```

# Module Functions

## Export-StigCKL 
 Saves a loaded CKL file to disk
```
Export-StigCKL -CKLData $CKLData -Path "C:\CKLs\MyCKL.ckl"
```
or
```
Export-StigCKL -CKLData $CKLData -Path "C:\CKLs\MyCKL.ckl" -AddHostData
```

## Get-CKLHostData 
 Gets the host information from the CKLData (IP, MAC, etc)
```
Get-CKLHostData -CKLData $CKLData
```

## Get-StigInfoAttribute 
Gets a stig info attribute, literally value of a "SI_DATA" under the "STIG_INFO" elements from the XML data of the CKL. This contains general information on the STIG file itself. (Version, Date, Name)
```
Get-StigInfoAttribute -CKLData $CKLData -Attribute "Version"
```

## Get-StigMetrics 
 Returns a complex object of metrics on the status of the checks in the specified directory.
```
Get-StigMetrics -CKLDirectory "C:\CKLS\"
```
### Return object format
```
This is an example showing the format of this function's output. This function will display different views of the same data.
@{
   IndividualVulnScores=@(
      [PSCustomObject]@{NotAFinding=1;Open=0;NotReviewed=0;NotApplicable=0;VulnID="V-00000"},
      [PSCustomObject]@{NotAFinding=0;Open=1;NotReviewed=0;NotApplicable=0;VulnID="V-00001"},
      [PSCustomObject]@{NotAFinding=0;Open=0;NotReviewed=0;NotApplicable=1;VulnID="V-00002"}
   );
   CategoryScores=@{
      Cat1=[PSCustomObject]@{Total=200; NotApplicable=50; NotReviewed=50; Open=50; NotAFinding=50;UniqueTotal=200};
      Cat2=[PSCustomObject]@{Total=200; NotApplicable=50; NotReviewed=50; Open=50; NotAFinding=50;UniqueTotal=200};
      Cat3=[PSCustomObject]@{Total=200; NotApplicable=50; NotReviewed=50; Open=50; NotAFinding=50;UniqueTotal=200};
   };
   TotalFindingScores=[PSCustomObject]@{Total=200; NotApplicable=50; NotReviewed=50; Open=50; NotAFinding=50}
}
```

## Get-VulnCheckResult 
 Gets the status of a single vuln check, or an array of the status of all vuln checks in a CKL
```
Get-VulnCheckResult -CKLData $CKLData -VulnID "V-11111"
```

## Get-VulnFindingAttribute 
 Gets a vuln's finding attribute (Status, Comments, Details, etc)
```
Get-VulnFindingAttribute -CKLData $CKLData -VulnID "V-1111" -Attribute "COMMENTS"
```

## Get-VulnIDs 
 Returns all VulnIDs contained in the CKL
```
Get-VulnIDs -CKLData $CKLData
```

## Get-VulnInfoAttribute 
 Gets a vuln's informational attribute
```
Get-VulnInfoAttribute -CKLData $CKLData -Attribute "Version"
```

## Get-XCCDFHostData 
 Gets host info from XCCDF
```
Get-XCCDFHostData -XCCDF $XCCDFData
```

## Get-XCCDFResults 
 Returns stig results from an XCCDF file
```
Get-XCCDFResults -XCCDF (Import-XCCDF -Path C:\XCCDF\Results.xml)
```

## Import-StigCKL 
 Load a CKL file as an [XML] element. This can then be passed to other functions in this module.
```
$CKLData = Import-StigCKL -Path "C:\CKLs\MyCKL.ckl"
```

## Import-XCCDF 
Load an XCCDF file into a [xml]
```
$XCCDFData = Import-XCCDF -Path C:\XCCDF\Results.xml
```

## Merge-CKLData 
 Merges two loaded CKLs, entries in source will overwrite entries in destination.
```
Merge-CKLData -SourceCKL $OriginalInfo -DestinationCKL $NewCKL
```

## Merge-CKLs 
 Merges two CKL files and saves it as a new CKL. Largely a wrapper around Merge-CKLData. By default, this does not merge items marked Not_Reviewed. The idea here is if you have a check that will be the same for **all** checklists of the same type, this can be used to bulk answer those questions. (For example, checks concerning physical security of your datacenter will likely be the same for all checklists for servers that reside in the same datacenter)
```
Merge-CKLs -DestinationCKLFile "C:\CKLS\Blank.ckl" -DestinationCKLFile "C:\CKLS\Answered.ckl" -SaveFilePath "C:\CKLS\Merged.ckl"
```
or, to also merge over things marked Not_Reviewed
```
Merge-CKLs -DestinationCKLFile "C:\CKLS\Blank.ckl" -DestinationCKLFile "C:\CKLS\Answered.ckl" -SaveFilePath "C:\CKLS\Merged.ckl" -IncludeNR
```

## Merge-XCCDFHostDataToCKL 
 Adds XCCDF host info into a loaded CKL data (IP, Mac, etc)
```
Merge-XCCDFHostDataToCKL -CKLData $CKLData -XCCDF $XCCDFData
```

## Merge-XCCDFToCKL 
 Adds XCCDF results into a loaded CKL data (Same as using STIG Viewer to import SCAP results into a manual checklist, but this can be used to do it in bulk)
```
Merge-XCCDFToCKL -CKLData $CKLData -XCCDF $XCCDFData
```

## Repair-StigCKL 
 Opens and resaves a CKL, may fix formatting issues
```
Repair-StigCKL -Path "C:\CKLs\MyCKL.ckl"
```

## Set-CKLHostData 
 Sets host data in CKL. If any parameters are blank, they will be set to running machine
```
Set-CKLHostData -CKLData $CKLData -Host "SomeMachine" -FQDN "SomeMachine.Some.Domain.com" -Mac "00-00-00-..." -IP "127.0.0.1"
```
or to set to the running host
```
Set-CKLHostData -CKLData $CKLData 
```

## Set-VulnCheckResult 
 Sets the findings information for a single vuln
```
Set-VulnCheckResult -CKLData $CKLData -VulnID "V-11111" -Details "Not set correctly" -Comments "Checked by xyz" -Result Open
```

## Set-VulnCheckResultFromRegistry 
 Sets a vuln status based on a registry check
```
Set-VulnCheckResultFromRegistry -CKLData $CKLData -RegKeyPath "HKLM:\SOFTWARE\COMPANY\DATA" -RequiredKey "PortStatus" -RequiredValue "Closed" -Comments "Checked by asdf"
```

## Set-VulnFindingAttribute 
 Sets a vuln's finding attribute (Status, Comments, Details, etc)
```
Set-VulnFindingAttribute -CKLData $CKLData -VulnID "V-1111" -Attribute "COMMENTS" -Value "This was checked by script"
```

## Get-CheckListInfo
Gets general info from the checklist (Release, Title, Description)
```
Get-CheckListInfo -CKLData $CKLData
```
### Output Format
```
[PSObject]@{Title="";Description="";Release="";}
```

## Get-XCCDFInfo
Gets general info from the xccdf (Release, Title, Description)
```
Get-XCCDFInfo -XCCDF $XCCDFData
```
### Output Format
```
[PSObject]@{Title="";Description="";Release="";}
```

## Get-XCCDFVulnInformation
Returns an array of the vulns in the xccdf file (ID, Title, Version, Description/VulnDiscussion, FixText, CheckText)
```
Get-XCCDFVulnInformation -XCCDF $XCCDFData
```
### Output Format
```
@{ID="";Title="";Version="";Description="";FixText="";CheckText=""}
```

## Get-CKLVulnInformation
Returns an array of the vulns in the CKL file (ID, Title, Version, Description/VulnDiscussion, FixText, CheckText)
```
Get-CKLVulnInformation -CKLData $CKLData
```
### Output Format
```
@{ID="";Title="";Version="";Description="";FixText="";CheckText=""}
```