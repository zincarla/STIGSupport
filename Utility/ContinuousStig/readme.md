# Continuous STIG
This part of the repo is still being developed. The end goal is to have a script that downloads the STIG library, updates old CKLs and includes results from fresh SCAP scans automatically.

## Terminology
- Scap Content: Content file for the SCAP tool
- Manual File: A xccdf xml file as downloaded from the DISA STIG Library. This is usually what is used to create CKL files in the StigViewer application.
- ScapMapping File: A json file that tells the script what Scap Content file and what Manual File relate to a STIG ID. (So the script know which CKL to merge SCAP scans into as well as what manual file to use to update old CKLs based on ID)

## Start-CSUpdate
This script will use a SCAP Content directory, CKL directory, and the latest STIG library to:
. SCAP scan hosts based on data within the pre-exinsting CKL files (Optional)
. Merge old CKL results into new CKL generated from the latest STIG
. Merge SCAP results to that if SCAP results exists
. Report on checks that still require manual attention

## New-ScapMap
This script automatically creates a ScapMapping file for use with Start-CSUpdate. This file can be updated manually and may need to be if it is unable to properly relate SCAP and manual files.

## New-StigLibrary
This script will download the DISA non-FOUO library and extract the files to a directory.

## Example Usage
* Create a SCAP repo and extract SCAP content files to it. Even if you do not use the SCAP portion, the directory is still used.
* Create a CKL repo that has answered or partially answered CKL files in it. Must include the host if using SCAP scan feature! (So SCAP knows what to scan)
* Download the STIG Library and extract it. (Using New-StigLibrary.ps1)
* Once all repos are setup, create a SCAP mapping file (Using New-ScapMap.ps1)
    - The name is a bit misleading, the purpose of this file is to track what STIG ID goes to what Manual check file and what SCAP content file. The SCAP portion is optional.
    - The SCAP and Manual portions should be regex patterns. This can help "future-proof" the file by matching SCAP content and manual files even with different versions.
* Then you can run Start-CSUpdate.ps1

```powershell
# Assuming you have a directory called C:\StigCKLs with old CKL files in them
# And Assuming you have downloaded and extracted SCAP content to C:\ScapContent
#    Though this is optional, if not provided, scap scans will be skipped but CKL files will still be updated to latest STIG version
# And you created a folder called C:\StigStaging

# Download DISA Stig Library
&"New-StigLibrary.ps1" -Staging "C:\StigStaging"

# Create a SCAP Mapping File Automatically
"&New-ScapMap.ps1" -Staging "C:\StigStaging" -CKLDirectory "C:\StigCKLs" -ScapRepository "C:\ScapContent"

# Now we can automatically update CKL files
&"Start-CSUpdate.ps1" -Staging "C:\StigStaging" -CKLDirectory "C:\StigCKLs" -ScapRepository "C:\ScapContent" -ReportPath "C:\StigCKLs\UpgradeReport.txt" -SetNROnChange

# Once complete, the CKL files in C:\StigCKLs should be updated. Review the report to see what checks are left that require a manual check
```