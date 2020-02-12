<#
.SYNOPSIS
    Compares the latest stig library against a provided repository of checklists

.DESCRIPTION
    The idea, is that you have a CKL repo, SCAP repo, and the latest DISA STIG Library extracted. This script 
    will run SCAP scans based on the CKLs in the CKL Repo. The SCAP scan is then merged into the latest manual
    checks from the STIG library. Then, it merges with the pre-existing CKL file. This is so the SCAP can
    automatically account for changes that the SCAP has been updated to handle. New checks that may not be
    handled are reported in CKL, and checks that SCAP cannot handle, but were previously answered, stay answered.

.PARAMETER Staging
    The directory containing the extracted STIGs. Should be the same as passed to New-StigLibrary.ps1

.PARAMETER CKLDirectory
    Directory containing the CKL files to process.

.PARAMETER EmailRecipients
    Array of recipients for e-mail

.PARAMETER EmailServer
    Server to email from

.PARAMETER EmailFrom
    Email address to send from

.PARAMETER EmailSubject
    Subject of Email

.PARAMETER ReportSavePath
    Location to save the script output

.PARAMETER ScapRepository
    Location containing SCAP content and Scap Mapping file

.PARAMETER ScapTool
    Location of SCAP Compliance Checker Executable

.PARAMETER SetNROnChange
    Sets a check to open if the check content changed between STIG versions
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
    [Parameter(Mandatory=$true)]$ScapRepository,
    $ScapTool="C:\Program Files\SCAP Compliance Checker 5.1\cscc.exe",
    [switch]$SetNROnChange
)

#Ensure we have pre-req module imported
if ((Get-Module|Where-Object -FilterScript {$_.Name -eq "StigSupport"}).Count -le 0) {
    Write-Error "Please import StigSupport.psm1 before running this script"
    return
}

#Metrics
$StartTime = [DateTime]::Now
$ItemsRequiringReview = 0;
$FilesRequiringReview = 0;
$CKLsSkipped = 0;
$Report = ""
#Various paths
$LibraryPath = "$Staging\Library"
$SubLibraryPath = $LibraryPath+"\STIGS"
$MappingPath = (Join-Path -Path $ScapRepository -ChildPath "ScapMappings.json")
$BackupDir = (Join-Path -Path $CKLDirectory -ChildPath "Backups-$(Get-Date -Format "yyyy-MM-dd HH-mm-ss")")
#Cache some file data
$ScapFiles = Get-ChildItem -Path $ScapRepository -Filter "*Benchmark.xml" -Recurse
$ManualFiles = Get-ChildItem -Path $SubLibraryPath -Filter "*manual-xccdf.xml" -Recurse
$CKLFiles = Get-ChildItem -Path $CKLDirectory -Recurse -Include "*.ckl" -File | Where-Object { $_.FullName -notmatch ".*\\Backups-" }

#For file names
$DateT = Get-Date -Format "yyyy-MM-dd-HH-mm"

#helper function
<#
.SYNOPSIS
    This function will return an item, or list of items that have a property named $property with a value that regex matches $MatchRule
#>
function Get-ItemWithPropertyInListMatches {
    Param($List, $Property, $MatchRule)
    return ($List | Where-Object {$_.$Property -match $MatchRule})
}

#Process
#Update SCAP Content : Cannot be automated ;(
#Load scap mapping JSON file
Write-Host "Loading SCAP Mapping File"
if (Test-Path -Path $MappingPath) {
    $ScapMappingsContent = Get-Content -Path $MappingPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    $ScapMappings = New-Object System.Collections.ArrayList(,$ScapMappingsContent) #So we can remove items later
} else {
    #Create Example if not already
    if (-not (Test-Path -Path (Join-Path -Path $ScapRepository -ChildPath "ScapMappingsExample.json"))) {
        $Data = New-Object -TypeName PSObject -Property @{SCAP="U_Benchmark.xml";Manual="U_MAN.xml";ID="SomeCompany_SomeItem_SomeStig"}
        $Data2 = New-Object -TypeName PSObject -Property @{SCAP="";Manual="U_MAN_2.xml";ID="SomeCompany_SomeItem_SomeStig"}

        @($Data,$Data2) | ConvertTo-Json | Out-File (Join-Path -Path $ScapRepository -ChildPath "ScapMappingsExample.json")
    }
    Write-Error "Scap mappings were not found. This script requires mappings. Cancelling."
    $Report += "ERROR: Scap mapping file was not found. Cancelling`r`n"
    return
}

Write-Host "Verifying SCAP Mappings"
#Clean up scap mappings that are missing or ambiguous and cache the matching files
for ($I =0; $I -lt $ScapMappings.Count; $I++) {
    #Check that manual and ID are present, and then unpack to their full file path
    if ($ScapMappings[$I].Manual -eq $null -or$ScapMappings[$I].Manual -eq "" -or $ScapMappings[$I].ID -eq "" -or $ScapMappings[$I].ID -eq $null) {
        $Report+="WARN: Manual information and ID are required at a minimum for the SCAP mappings. This is missing for $($ScapMappings[$I].ID) :: $($ScapMappings[$I].Manual). Skipping.`r`n"
        $ScapMappings.RemoveAt($I)
        $I--;
        continue #Skip rest of current iteration of loop as item removed
    }
    else 
    {
        $MatchingManualFiles = @()+(Get-ItemWithPropertyInListMatches -List $ManualFiles -Property "Name" -MatchRule $ScapMappings[$I].Manual)
        if ($MatchingManualFiles.Length -ne 1) {
            if ($MatchingManualFiles.Length -gt 1) {
                $Report+="WARN: $($MatchingManualFiles.Length) Ambiguous Manual files found for $($ScapMappings[$I].ID) :: $($ScapMappings[$I].Manual). Skipping.`r`n"
                foreach ($MMF in $MatchingManualFiles) {
                    $Report+="`t$($MMF.FullName)`r`n"
                }
            }
            if ($MatchingManualFiles.Length -lt 1) {
                $Report+="WARN: No Manual files found for $($ScapMappings[$I].Manual). Skipping.`r`n"
            }
            $ScapMappings.RemoveAt($I)
            $I--;
            continue #Skip rest of current iteration of loop as item removed
        }
        else {
            $ScapMappings[$I].Manual = $MatchingManualFiles[0].FullName
        }
    }
    if ($ScapMappings[$I].SCAP -ne $null -and $ScapMappings[$I].SCAP -ne "") {
        $MatchingScapFiles = @()+(Get-ItemWithPropertyInListMatches -List $ScapFiles -Property "Name" -MatchRule $ScapMappings[$I].SCAP)
        if ($MatchingScapFiles.Length -ne 1) {
            if ($MatchingScapFiles.Length -gt 1) {
                $Report+="WARN: Ambiguous SCAP files found for $($ScapMappings[$I].SCAP). Skipping.`r`n"
            }
            if ($MatchingScapFiles.Length -lt 1) {
                $Report+="WARN: No SCAP files found for $($ScapMappings[$I].SCAP). Skipping.`r`n"
            }
            $ScapMappings.RemoveAt($I)
            $I--;
        }
        else {
            $ScapMappings[$I].SCAP = $MatchingScapFiles[0].FullName
        }
    }
    Write-Progress -Activity "Verifying SCAP Mappings" -PercentComplete ($I*100/$ScapMappings.Count)
}
Write-Progress -Activity "Verifying SCAP Mappings" -Completed

Write-Host "Caching CKL Metadata"
#Cache CKL Data
$CKLCache = @() #@{ID = $CKLI.ID; Path=$File.FullName; Host = $HostName; ScapMapping=$MatchingScap; SCAPResultPath}
$I=0;
foreach ($File in $CKLFiles) {
    #Load CKL File
    $CKLData = Import-StigCKL -Path $File.FullName
    #Get STIG Name
    $CKLI = Get-CheckListInfo -CKLData $CKLData
    $HostName = (Get-CKLHostData -CKLData $CKLData).HostName

    $MatchingScap = @()+(Get-ItemWithPropertyInListMatches -List $ScapMappings -Property "ID" -MatchRule $CKLI.ID)
    if ($MatchingScap -ne $null -and $MatchingScap.Length -eq 1) {
        $CKLCache += New-Object -TypeName PSObject -Property @{ID = $CKLI.ID; Path=$File.FullName; Host = $HostName; ScapMapping=$MatchingScap; SCAPResultPath=""}
        if (($HostName -eq $null -or $HostName -eq "") -and $ScapMappings -ne $null) {
            $Report += "WARN: $($File.FullName) is missing host information. Scap will be skipped for this.`r`n"
        }
    }
    elseif ($MatchingScap.Length -lt 1)
    {
        $Report += "WARN: $($File.FullName) does not have matching information in the Scap Mappings. Will be skipped.`r`n"
        $CKLsSkipped ++;
    }
    elseif ($MatchingScap.Length -gt 1)
    {
        $Report += "WARN: $($File.FullName) has ambiguous matching information in the Scap Mappings. Will be skipped.`r`n"
        $Report += $MatchingScap[0].ToString()+"::"+$CKLI.ID+"`r`n"
        $CKLsSkipped ++;
    }
    
    Write-Progress -Activity "Caching CKL Metadata" -PercentComplete ($I*100/$CKLFiles.Count)
    $I++;
}
Write-Progress -Activity "Caching CKL Metadata" -Completed

$Report += "$($CKLCache.Length) previous CKLs found with another $CKLsSkipped skipped.`r`n"

#Scan Targets using SCAP
#Prepare Results Directory
$ResultsPath = Join-Path $ScapRepository -ChildPath "Results-$DateT"
Remove-Item -Path $ResultsPath -ErrorAction SilentlyContinue -Recurse
if (-not (Test-Path $ResultsPath)) {
    New-Item -Path $ResultsPath -ItemType Directory | Out-Null
}

function Start-ScapProcess {
    Param($FilePath,$ArgumentList,[switch]$PrintOut,[switch]$PrintError)
    # Quick note here, you must use asynch on all but one output stream when using process to avoid deadlock
    # https://docs.microsoft.com/en-us/dotnet/api/system.diagnostics.processstartinfo.redirectstandardoutput
    $Process = New-Object -TypeName System.Diagnostics.Process
    $Process.StartInfo.FileName = $FilePath
    $Process.StartInfo.Arguments = $ArgumentList
    $Process.StartInfo.RedirectStandardOutput = $true
    $Process.StartInfo.RedirectStandardError = $true
    $Process.StartInfo.UseShellExecute = $false
    $Process.StartInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
    $ErrEventScript = {
        if ($EventArgs.Data -ne $null -and -not [string]::IsNullOrWhiteSpace($EventArgs.Data)) {
            Write-Warning "Scap Error: $($EventArgs.Data)"
        }
    }
    $ErrEvent = Register-ObjectEvent -InputObject $Process -Action $ErrEventScript -EventName 'ErrorDataReceived'
    $Process.Start() | Out-Null

    if ($PrintError) {
        $Process.BeginErrorReadLine()
    }
    while (-not $Process.HasExited) {
        $NextLine = ""
        
        if (-not $Process.StandardOutput.EndOfStream){
            $NextLine = $Process.StandardOutput.ReadLine()
            if ($PrintOut) {
                Write-Host $NextLine
            }
        }
        if ($NextLine -match "Processing Rule : \((\d+) of (\d+)\).*") {
            Write-Progress -Activity "Scap Scan" -Status "Scanning ($($Matches[1]) / $($Matches[2]))" -PercentComplete (($Matches[1]/$Matches[2])*100)
        }
    }
    Write-Progress -Activity "Scap Scan" -PercentComplete 100 -Completed
    Unregister-Event -SourceIdentifier $ErrEvent.Name #Cleanup
    $Process.Dispose()
}

Write-Host "Starting SCAP Scan Cycle"
#This bit could be better I imagine. Right now, it clears SCAP tool of content, then adds content, scans, removes content, one at a time
$PreviousScapContent = $null
for ($Index =0; $Index -lt $CKLCache.Length; $Index++) {
    #We skip the SCAP scan if this CKL does not have matching SCAP content
    if ($CKLCache[$Index].ScapMapping.SCAP -ne "" -and $CKLCache[$Index].ScapMapping.SCAP -ne $null) {
        Write-Host "Scanning $($CKLCache[$Index].Host) for $($CKLCache[$Index].ID)"

        #Prepare CSCC
        if ($PreviousScapContent -eq $null -or $PreviousScapContent -ne $CKLCache[$Index].ScapMapping.SCAP) {
            Write-Host "`tPreparing Scap Tool"
            Write-Progress -Activity "Preparing Scap" -Status "Preparing (0/3)" -PercentComplete ((0/3)*100)
            Start-ScapProcess -FilePath $ScapTool -ArgumentList @("-ua") -PrintError #Remove all SCAP Content
            Write-Progress -Activity "Preparing Scap" -Status "Preparing (1/3)" -PercentComplete ((1/3)*100)

            Start-ScapProcess -FilePath $ScapTool -ArgumentList @("-iv", $CKLCache[$Index].ScapMapping.SCAP) -PrintError #Install Content
            Write-Progress -Activity "Preparing Scap" -Status "Preparing (2/3)" -PercentComplete ((2/3)*100)

            Start-ScapProcess -FilePath $ScapTool -ArgumentList @("-ea") -PrintError #Enable Content
            Write-Progress -Activity "Preparing Scap" -Status "Preparing (3/3)" -Completed


            $PreviousScapContent = $CKLCache[$Index].ScapMapping.SCAP
        }
        #Scan
        Write-Host "`tPerforming Scan"
        if (Test-Connection $CKLCache[$Index].Host) {
            Start-ScapProcess -FilePath $ScapTool -ArgumentList @("-h",$CKLCache[$Index].Host,"-u",$ResultsPath) -PrintError #Scan target
        } else {
            Write-Warning "Could not connect to $($CKLCache[$Index].Host)"
        }
        #Get Results and cache
        $ResultFile = @()+( Get-ChildItem -Path $ResultsPath -Filter "$($CKLCache[$Index].Host)*XCCDF-Results*$($CKLCache[$Index].ID)*.xml" -Recurse -ErrorAction SilentlyContinue)
        if ($ResultFile.Length -eq 1) {
            $CKLCache[$Index].ScapResultPath = $ResultFile[0].FullName
        }
        elseif ($ResultFile.Length -gt 1) {
            $Report += "WARN: Ambiguous results found for $($CKLCache[$Index].Host) on $($CKLCache[$Index].ID)"
            Write-Warning "Ambiguous results found for $($CKLCache[$Index].Host) on $($CKLCache[$Index].ID)"
        }
        elseif ($ResultFile.Length -lt 1) {
            $Report += "WARN: Results not found for $($CKLCache[$Index].Host) on $($CKLCache[$Index].ID)"
            Write-Warning "Results not found for $($CKLCache[$Index].Host) on $($CKLCache[$Index].ID)"
        }
    }
    Write-Progress -Activity "SCAP Scanning" -PercentComplete ($Index*100/$CKLCache.Length)
}
Write-Progress -Activity "SCAP Scanning" -Completed


#Grab required Manual XCCDFs and convert them to CKLS
Write-Host "Preparing template CKL files"
$BlankCKLTable = @{}
$I=0;
foreach($CKL in $CKLCache) {
    if (-not $BlankCKLTable.ContainsKey($CKL.ID) -and $CKL.ScapMapping.Manual -ne "" -and $CKL.ScapMapping.Manual -ne $null) {
        #Convert to CKL
        Convert-ManualXCCDFToCKL -XCCDFPath $CKL.ScapMapping.Manual -SaveLocation $CKL.ScapMapping.Manual.Replace(".xml", ".ckl")
        $BlankCKLTable += @{$CKL.ID=$CKL.ScapMapping.Manual.Replace(".xml", ".ckl")}
    }
    Write-Progress -Activity "Preparing template CKL files" -PercentComplete ($I*100/$CKLCache.Length)
    $I++;
}
Write-Progress -Activity "Preparing template CKL files" -Completed


#Merge Results
#Create Backup
if (-not (Test-Path $BackupDir)) {
    New-Item -Path $BackupDir -ItemType Directory | Out-Null
}
$I=0
foreach ($CKL in $CKLCache) {
    Write-Host "Merging results for $($CKL.Host) :: $($CKL.ID)"
    #Load Result
    $ResultXCCDF = $null
    if ($CKL.ScapResultPath -ne "" -and $CKL.ScapResultPath -ne $null) {
        $ResultXCCDF = Import-XCCDF -Path $CKL.ScapResultPath
    }

    #Load Template
    $TemplateCKL = $null
    if (-not $BlankCKLTable.ContainsKey($CKL.ID)) {
        $Report += "WARN: Manual content for $($CKL.ID) was not found. This file will not be updated."
        Write-Warning "Manual content for $($CKL.ID) was not found. This file will not be updated."
        continue
    }
    $TemplateCKL = Import-StigCKL -Path $BlankCKLTable[$CKL.ID]

    #Load previous CKL
    $OldCKL = Import-StigCKL -Path $CKL.Path

    #Cache changes before merge so we can set to NR
    $CKLChanges = @()
    if ($SetNROnChange) {
        Write-Host "`tComparing new and old CKLs"
        $OldChecks = Get-VulnInformation -CKLData $OldCKL -NoAliases
        $NewChecks = Get-VulnInformation -CKLData $TemplateCKL -NoAliases
        foreach ($NewCheck in $NewChecks) {
            $MatchingCheck = $OldChecks | Where-Object {$_.Vuln_Num -eq $NewCheck.Vuln_Num}
            if ($MatchingCheck) {
                #Verify if different (Version or Check_Content is different. We ignore white-space in Check_Content
                if ($MatchingCheck.Version -ne $NewCheck.Version -or
                    ($MatchingCheck.Check_Content -replace "\s","") -ne ($NewCheck.Check_Content -replace "\s","")) {
                    $CKLChanges += $MatchingCheck.Vuln_Num
                }
            }
        }
        $Report += "INFO: Found $($CKLChanges.Length) changes to $($CKL.Host) :: $($CKL.ID), these may need to be manually checked depending on SCAP scan"
    }

    #Merge Previous CKL to results
    Write-Host "`tMerging CKL"
    Merge-CKLData -SourceCKL $OldCKL -DestinationCKL $TemplateCKL

    if ($SetNROnChange) {
        #Set any results that changed to NR
        foreach ($Change in $CKLChanges) {
            Set-VulnCheckResult -CKLData $TemplateCKL -Result Not_Reviewed -VulnID $Change
        }
    }

    #Merge Result to Template
    if ($ResultXCCDF -ne $null) {
        Write-Host "`tMerging XCCDF"
        Merge-XCCDFToCKL -CKLData $TemplateCKL -XCCDF $ResultXCCDF -NoCommentsOnOpen
    }
    
    #Backup previous CKL
    $FileName = (Get-Item -Path $CKL.Path).Name
    $NewFullPath = Join-Path -Path $BackupDir -ChildPath ( $CKL.Path.Replace($CKLDirectory,""))
    $NewPathDir = Split-Path -Path $NewFullPath -Parent
    if (-not (Test-Path -Path $NewPathDir)) {
        New-Item -Path $NewPathDir -ItemType Directory | Out-Null
    }
    try {
        Move-Item -Path $CKL.Path -Destination $NewFullPath -ErrorAction Stop
    } catch {
        Write-Warning "Could not backup $($CKL.Path)" #Downgrade this to a warning
    }

    #Overwrite CKL
    Export-StigCKL -CKLData $TemplateCKL -Path $CKL.Path

    #Log NR
    $StigResults = Get-VulnCheckResult -CKLData $TemplateCKL
    $NR = (@()+($StigResults | Where-Object {$_.Status -eq "Not_Reviewed"})).Length
    $Opens = (@()+($StigResults | Where-Object {$_.Status -eq "Open"})).Length
    if ($NR -ne 0) {
        $FilesRequiringReview ++;
        $ItemsRequiringReview += $NR;
        $Report+="Result: $($CKL.Path) needs to be reviewed as it has $NR Not Reviewed and $Opens open`r`n"
    } elseif ($Opens -ne 0) {
        $Report+="Result: $($CKL.Path) has $Opens open`r`n"
    }
    Write-Progress -Activity "Merging CKLs" -Id 1 -PercentComplete ($I*100/$CKLCache.Length)
    $I++
}
Write-Progress -Activity "Merging CKLs" -Id 1 -Completed


#Metrics and end
$TotalTime = ([DateTime]::Now - $StartTime).TotalMinutes

$Report += "-=Metrics=-`r`n"
$Report += "There are $ItemsRequiringReview items to be reviewed in $FilesRequiringReview files`r`n"
$Report += "This script took $TotalTime minutes to complete`r`n"

#If changes have been found, send the report out
$Report | Out-File $ReportSavePath
if ($Report -ne "" ) {
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
}