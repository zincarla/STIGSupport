<#
.SYNOPSIS
    Compares the latest stig library against a provided repository of checklists

.DESCRIPTION
    Downloads the NON-FOUO stig library for the current month, extracts it, then compares it to a directory of checklist files. 
    Potential changes and new checks are documented, then sent to the specified recipients. The idea with this script is that
    it can be set to run as a scheduled task, alerting people to relevant changes in the STIGs. These changes could then be 
    addressed immediately.

.PARAMETER Staging
    The directory the library will be downloaded and extracted to.

.PARAMETER CKLDirectory
    The directory containing all your CKL files.

.PARAMETER EmailRecipients
    An array of recipients to receive the report

.PARAMETER EmailServer
    SMTP Server name/ip

.PARAMETER EmailFrom
    Address to send from

.PARAMETER EmailSubject
    Subject of the e-mail, defaults to "Potential work required on ckl files"

.PARAMETER ReportSavePath
    Place to save the report as text file defaults to "C:\Users\Public\STIGReport.txt"

.PARAMETER IgnoreMinorChanges
    By default, any changes between the ckl files and the library files are reported. If this is set to true, changes in descriptions, changes in versions, and extraneous checks in ckl files are ignored.

.PARAMETER ExtractionRepository
    Path to a directory. If set, this script will also extract the stig library to this location. This allows you to use the script to also maintain an up-to-date repository of stigs

.PARAMETER LibraryURL
    URL to the STIG Library to download (Defaults to the assumed location of the current NON-FOUO library)

.PARAMETER NoDownload
    Prevent the script from re-downloading/extracting the STIG files. This is good for if you needed to manually change some library files (Remove duplicates, fix permissions). Or are re-running a comparison.

.EXAMPLE
    ContinuousSTIG.ps1 -CKLDirectory "\\MyShare\MyChecklists" -EmailServer "MySMTPServer" -EmailRecipients @("myadmin@mydomain.com", "mytest@test.com") -EmailFrom "STIGReport@mydomain.com"

.EXAMPLE
    ContinuousSTIG.ps1 -CKLDirectory "\\MyShare\MyChecklists" -EmailServer "MySMTPServer" -EmailRecipients @("myadmin@mydomain.com", "mytest@test.com") -EmailFrom "STIGReport@mydomain.com" -NoDownload

.EXAMPLE
    ContinuousSTIG.ps1 -CKLDirectory "\\MyShare\MyChecklists" -Staging "C:\WorkingDir\Staging" -ReportSavePath "\\Reports\MyReports\Report.txt" -ExtractionRepository "\\tools\extractedstigs"
#>
Param
(
    $Staging="C:\Users\Public\Staging",
    [Parameter(Mandatory=$true)]$CKLDirectory,
    $EmailRecipients,
    $EmailServer,
    $EmailFrom,
    $EmailSubject = "Potential work required on ckl files",
    $ReportSavePath="C:\Users\Public\STIGReport.txt",
    $ExtractionRepository,
    [switch]$IgnoreMinorChanges,
    $LibraryURL = "http://iasecontent.disa.mil/stigs/zip/Compilations/U_SRG-STIG_Library_$([DateTime]::Now.Year)_$([DateTime]::Now.ToString("MM")).zip",
    [Switch]$NoDownload
)

#Metrics
$MajorChanges =0
$MinorChanges =0
$StartTime = [DateTime]::Now

#Ensure we have pre-req module imported
if ((Get-Module|Where-Object -FilterScript {$_.Name -eq "StigSupport"}).Count -le 0) {
    Write-Error "Please import StigSupport.psm1 before running this script"
    exit 1
}

#Add .net assembly for extracting zips
Add-Type -AssemblyName System.IO.Compression.FileSystem

#Download the new library
$URL = $LibraryURL
$ZipPath = "$Staging\library.zip"
$LibraryPath = "$Staging\Library"
$SubLibraryPath = $LibraryPath+"\STIGS"

#Skip the download, and all extractions with this flag
if (-not $NoDownload) {

    try {
        if (Test-Path -Path $LibraryPath) {
            Remove-Item -Path $LibraryPath -Recurse -ErrorAction Stop
        }
        if (Test-Path -Path $ZipPath) {
            Remove-Item -Path $ZipPath -ErrorAction Stop
        }
        Write-Host "Downloading the DISA Stig Library"
        $Trash = Invoke-WebRequest -Uri $URL -OutFile $ZipPath -ErrorAction Stop
    } catch {
        Write-Error "Failed prepare staging area, or download new library"
        #TODO: Alert on failure
        exit 1
    }

    #Extract it to the staging directory
    try {
        Write-Host "Extracting library to $LibraryPath"
        $Trash = [System.IO.Compression.ZipFile]::ExtractToDirectory($ZipPath, $LibraryPath)
        if ($ExtractionRepository -ne $null) {
            if (Test-Path $ExtractionRepository) {
                Get-ChildItem -Path $ExtractionRepository -Recurse | Remove-Item -Recurse
            } else {
                $Trash = New-Item -Path $ExtractionRepository -ItemType Directory
            }
            Write-Host "Copying extracted library to $ExtractionRepository"
            $Trash = ROBOCOPY /MIR "$LibraryPath" "$ExtractionRepository"
        }
    } catch {
        Write-Error "Failed to unzip the library"
        #TODO: Alert on failure
        exit 1
    }

    $ZipFiles = Get-ChildItem -Path ($LibraryPath) -Filter "*.zip" -Recurse

    Write-Host "Extracting STIG zips. Errors will probably be thrown due to duplicate files. These can generally be ignored! These are usually supporting files and documentation (PDFs, Images, etc)"
    $I=0
    foreach ($Zip in $ZipFiles) {
        $Trash = [System.IO.Compression.ZipFile]::ExtractToDirectory($Zip.FullName, $SubLibraryPath+"\$($Zip.Name.Substring(0,$Zip.Name.Length-4))\")
        $I++
        Write-Progress -Activity "Extracting" -PercentComplete (($I/$ZipFiles.Count)*100)
    }
    Write-Progress -Activity "Extracting" -Completed

    #Some of the older files are double zipped
    $ZipFiles = Get-ChildItem -Path ($SubLibraryPath) -Filter "*.zip" -Recurse
    $I=0
    foreach ($Zip in $ZipFiles) {
        $Trash = [System.IO.Compression.ZipFile]::ExtractToDirectory($Zip.FullName, $SubLibraryPath+"\$($Zip.Name.Substring(0,$Zip.Name.Length-4))\")
        $I++
        Write-Progress -Activity "Extracting" -PercentComplete (($I/$ZipFiles.Count)*100)
    }
    Write-Progress -Activity "Extracting" -Completed
} else {
    Write-Host "Skipped download and extractions. Will work off of old files."
}

#Get a list of all xccdf files
$XCCDFs = Get-ChildItem -Path $LibraryPath -Filter "*manual-xccdf.xml" -Recurse

#Get a list of all ckl files
$CKLs = Get-ChildItem -Path $CKLDirectory -Filter "*.ckl" -Recurse

#Create an index of the XCCDF files
$XCCDFIndex = @{}
$I=0
foreach ($XCCDF in $XCCDFs) {
    $XCCDFData = Import-XCCDF -Path $XCCDF.FullName
    $XInfo = Get-XCCDFInfo -XCCDF $XCCDFData
    $XInfo | Add-Member -MemberType NoteProperty -Name "FilePath" -Value $XCCDF.FullName
    if ($XCCDFIndex.ContainsKey($XInfo.Title)) {
        #Duplicate key
        Write-Warning "Duplicate XCCDF Files: $($XCCDFIndex[$XInfo.Title].FilePath) <?> $($XInfo.FilePath)"
    } else {
        $XCCDFIndex += @{$XInfo.Title=$XInfo}
    }
    $I++
    Write-Progress -Activity "Indexing XCCDFs" -PercentComplete (($I/$XCCDFs.Count)*100)
}
Write-Progress -Activity "Indexing XCCDFs" -Completed

#Create an index of the CKL files
$CKLIndex = @()
$I=0
foreach ($CKL in $CKLs) {
    $CKLData = Import-XCCDF -Path $CKL.FullName
    $CInfo = Get-CheckListInfo -CKL $CKLData
    $CInfo | Add-Member -MemberType NoteProperty -Name "FilePath" -Value $CKL.FullName
    $CKLIndex += $CInfo
    $I++
    Write-Progress -Activity "Indexing CKLs" -PercentComplete (($I/$CKLs.Count)*100)
}
Write-Progress -Activity "Indexing CKLs" -Completed

#Compare the two indices and build a report
$Report = ""

$I =0
Write-Progress -Activity "Comparing Files" -Status "Starting" -PercentComplete 0 -Id 0
foreach ($CKLInfo in $CKLIndex) {
    #Contains the report for this file, allows us to not report if a minor change
    $SubReport = ""
    if ($XCCDFIndex.ContainsKey($CKLInfo.Title)) {
        #Found match
        if ($XCCDFIndex[$CKLInfo.Title].Release -ne $CKLInfo.Release) {
            $SubReport += $CKLInfo.FilePath + " needs to be checked (Release Difference)`r`n"
            $MinorChanges ++;
            $NonMinor=$false;
            #Explore changed rules
            Write-Progress -Activity "$($CKLInfo.FilePath)" -ParentId 0 -ID 1 -CurrentOperation "Loading XCCDF" -PercentComplete 0
            $XCCDFData = Import-XCCDF -Path $XCCDFIndex[$CKLInfo.Title].FilePath
            $XCCDFRules = Get-XCCDFVulnInformation -XCCDF $XCCDFData
            Write-Progress -Activity "$($CKLInfo.FilePath)" -ParentId 0 -ID 1 -CurrentOperation "Loading CKL" -PercentComplete 0
            $CKLData = Import-StigCKL -Path $CKLInfo.FilePath
            $CKLRules = Get-CKLVulnInformation -CKL $CKLData
            $R=0
            Write-Progress -Activity "$($CKLInfo.FilePath)" -ParentId 0 -ID 1 -CurrentOperation "Rules" -PercentComplete 0
            foreach ($CKLRule in $CKLRules) {
                $XCCDFPartner = $null
                $XCCDFPartner = $XCCDFRules | Where-Object {$_.ID -eq $CKLRule.ID}
                if ($XCCDFPartner -ne $null) {
                    if ($XCCDFPartner.FixText -ne $CKLRule.FixText) {
                        $SubReport += "`t$($CKLRule.ID) appears to have been updated (Fix Text)`r`n"
                        $NonMinor=$true
                        $MajorChanges++;
                    }
                    elseif ($XCCDFPartner.CheckText -ne $CKLRule.CheckText) {
                        $SubReport += "`t$($CKLRule.ID) appears to have been updated (Check Text)`r`n"
                        $NonMinor=$true
                        $MajorChanges++;
                    }
                    elseif ($XCCDFPartner.Version -ne $CKLRule.Version) {
                        if (-not $IgnoreMinorChanges) {
                            $SubReport += "`t$($CKLRule.ID) appears to have been updated (Version)`r`n"
                        }
                        $MinorChanges++;
                    }
                    elseif ($XCCDFPartner.Description -ne $CKLRule.Description) {
                        if (-not $IgnoreMinorChanges) {
                            $SubReport += "`t$($CKLRule.ID) appears to have been updated (Description)`r`n"
                        }
                        $MinorChanges++;
                    }
                } else {
                    if (-not $IgnoreMinorChanges) {
                        $SubReport += "`t$($CKLRule.ID) is no longer required, or is part of the FOUO library`r`n"
                    }
                    $MinorChanges++;
                }
                Write-Progress -Activity "$($CKLInfo.FilePath)" -ParentId 0 -ID 1 -CurrentOperation "Rules" -PercentComplete (($R/$CKLRules.Count)*100)
                $R++;
            }
            Write-Progress -Activity "$($CKLInfo.FilePath)" -ID 1 -Completed

            #Last step, find new rules
            foreach ($XCCDFRule in $XCCDFRules) {
                if (($CKLRules | Where-Object {$_.ID -eq $XCCDFRule.ID}).Count -eq 0) {
                    $SubReport += "`t$($XCCDFRule.ID) appears to be a new rule`r`n"
                    $NonMinor = $true
                    $MajorChanges++;
                }
            }

            if ($NonMinor -or -not $IgnoreMinorChanges) {
                #If this is a major change, or we are not ignoring minor changes, add to main report
                $Report += $SubReport +"`r`n"
            }
        }
    } else {
        if (-not $IgnoreMinorChanges) {
            $Report += $CKLInfo.FilePath + " not found in library?`r`n`r`n"
        }
        $MinorChanges++;
    }
    $I++;
    Write-Progress -Activity "Comparing Files" -Status "$I / $($CKLIndex.Count)" -PercentComplete (($I/$CKLIndex.Count)*100)
}

$TotalTime = ([DateTime]::Now - $StartTime).TotalMinutes

$Report += "-=Metrics=-`r`n"
$Report += "MinorChanges: $MinorChanges`r`n"
$Report += "MajorChanges: $MajorChanges`r`n"
$Report += "This script took $TotalTime minutes to complete"

#If changes have been found, send the report out
if ($Report -ne "" ) {
    $Report | Out-File $ReportSavePath
}
if ($EmailRecipients -ne $null -and $EmailServer -ne $null -and $EmailFrom -ne $null) {
    if ($EmailSubject -eq "") {
        $EmailSubject = "Potential work required on ckl files"
    }
    $smtp= New-Object System.Net.Mail.SmtpClient $EmailServer
    $msg = New-Object System.Net.Mail.MailMessage 
    $msg.To.Add($EmailRecipients)
    $msg.from = $EmailFrom
    $msg.subject = $EmailSubject
    $msg.body = $Report
    $msg.isBodyhtml = $false
    $smtp.send($msg)
    $smtp.Dispose();
    $msg.Dispose();
}