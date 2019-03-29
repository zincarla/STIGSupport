# Continuous STIG
This part of the repo is still being developed. The end goal is to have a script that downloads the STIG library, updates old CKLs and includes results from fresh SCAP scans automatically.

## Start-CSUpdate
This script will scan a SCAP Content directory, CKL directory, and the latest STIG library. Using a mapping file, it will run SCAP scans based on the CKLs found. The new SCAP scans, old answers in the orginal CKL and new STIG are all merged together to provide and updated CKL. If SCAP content is not available or provided, then the script just creates an updated CKL and migrates applicable answers from the old CKL.

### Usage
* Create a SCAP repo and extract SCAP content files to it. Even if you do not use the SCAP portion, the directory is still used.
* Create a CKL repo that has answered or partially answered CKL files in it. Must include the host if using SCAP scan feature! (So SCAP knows what to scan)
* Download the STIG Library and extract it. (Using New-StigLibrary.ps1)
* Once all repos are setup, create a SCAP mapping file (Using New-ScapMap.ps1)
    - The name is a bit misleading, the purpose of this file is to track what STIG ID goes to what Manual check file and what SCAP content file. The SCAP portion is optional.
    - The SCAP and Manual portions should be regex patterns. This can help "future-proof" the file by matching SCAP content and manual files even with different versions.
* Then you can run Start-CSUpdate.ps1

## New-ScapMap
This script automatically creates a ScapMapping file for use with Start-CSUpdate. This file can be updated manually and may need to be if it is unable to properly relate SCAP and manual files.

## New-StigLibrary
This script will download the DISA non-FOUO library and extract the files to a repository for use with Start-CSUpdate.

## Terminology
- Scap Content: Content file for the SCAP tool
- Manual File: A xccdf xml file as downloaded from the DISA STIG Library. This is usually what is used to create CKL files in the StigViewer application.
- ScapMapping File: A json file that tells the script what Scap Content file and what Manual File relate to a STIG ID. (So the script know which CKL to merge SCAP scans into as well as what manual file to use to update old CKLs based on ID)
