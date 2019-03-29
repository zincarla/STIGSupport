<#
.SYNOPSIS
    Downloads and extracts the NON-FOUO STIG Library

.DESCRIPTION
    Downloads and extracts the NON-FOUO STIG Library

.PARAMETER Staging
    The directory the library will be downloaded and extracted to.

.PARAMETER ExtractionRepository
    Path to a directory. If set, this script will also extract the stig library to this location. This allows you to use the script to also maintain an up-to-date repository of stigs

.PARAMETER LibraryURL
    URL to the STIG Library to download (Defaults to the assumed location of the current NON-FOUO library)

.EXAMPLE
    New-StigLibrary.ps1

.EXAMPLE
    New-StigLibrary.ps1 -Staging "C:\WorkingDir\Staging" -ExtractionRepository "\\tools\extractedstigs"
#>
Param
(
    $Staging="C:\Users\Public\Staging",
    $ExtractionRepository,
    $LibraryURL #If null, script will attempt to find latest one. This only pulls the NON-FOUO library.
)

#Metrics
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

#Download Library
try {
    if (Test-Path -Path $LibraryPath) {
        Remove-Item -Path $LibraryPath -Recurse -ErrorAction Stop
    }
    if (Test-Path -Path $ZipPath) {
        Remove-Item -Path $ZipPath -ErrorAction Stop
    }
    Write-Host "Downloading the DISA Stig Library"
} catch {
    Write-Error "Failed prepare staging area"
    exit 1
}

$AutoDate = [DateTime]::Now
$AutoRetryCount = 0
$Auto=$URL -eq $null

if (-not $Auto) {
    try {
    $Trash = Invoke-WebRequest -Uri $URL -OutFile $ZipPath -ErrorAction Stop
    } catch {
        Write-Error "Failed to download new library. $_"
        exit 1
    }
} else {
    Write-Host "Using automatic search for STIG library"
    #Loop through the urls and try to find the latest library if not already provided
    while ($true) {
        $URL = "http://iasecontent.disa.mil/stigs/zip/Compilations/U_SRG-STIG_Library_$($AutoDate.Year)_$($AutoDate.ToString("MM")).zip"
        Write-Host "Attempt $($AutoRetryCount+1) : $URL"
        try {
            $Trash = Invoke-WebRequest -Uri $URL -OutFile $ZipPath -ErrorAction Stop
            break
        } catch {
            $E = $_
            #Write-Host $E.ToString()
            Write-Host ($E.ToString().Contains("404") -or $E.ToString().Contains("Not found") -or $E.ToString().Contains("403") -or $E.ToString().Contains("Forbidden"))
            #404
            if ($E.ToString().Contains("404") -or $E.ToString().Contains("Not found") -or $E.ToString().Contains("403") -or $E.ToString().Contains("Forbidden")) {
                if ($AutoRetryCount -gt 5) {
                    Write-Error "Failed to download library, 404"
                    exit 1
                }
                $AutoDate = $AutoDate.AddMonths(-1)
                $AutoRetryCount++
            } else {
                Write-Error "Failed to download new library"
                exit 1
            }
        }
    }
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

$TotalTime = ([DateTime]::Now - $StartTime).TotalMinutes

$Report += "-=Metrics=-`r`n"
$Report += "This script took $TotalTime minutes to complete"

Write-Host $Report