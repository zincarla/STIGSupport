<#
.SYNOPSIS
    Saves a report of checklists that still have some non-reviewed entries

.DESCRIPTION
    Saves a report of checklists that still have some non-reviewed entries

.PARAMETER CKLDirectoryPath
    Directory to report on

.PARAMETER SavePath
    Location to save the output csv report

.PARAMETER Recurse
    Search entire directory structure or just specified folder

.OUTPUT
    One CSV report with details on non-reviewed checks

.EXAMPLE
    Export-NonReviewedReport.ps1 -CKLDirectoryPath C:\CKLs -SavePath C:\Reports\myreport.csv -recurse
#>
Param([Parameter(Mandatory=$true)]$CKLDirectoryPath, [Parameter(Mandatory=$true)]$SavePath, [switch]$Recurse)
#Check if module imported
if ((Get-Module|Where-Object -FilterScript {$_.Name -eq "StigSupport"}).Count -le 0)
{
    #End if not
    Write-Error "Please import StigSupport.psm1 before running this script"
    return
}

$Files = Get-ChildItem -Path $CKLDirectoryPath -Filter "*.ckl" -Recurse:$Recurse
$FormattedData = @()

Write-Progress -Activity "Processing" -PercentComplete 0
$Completed =0
#Loop through each of the CKL files
foreach ($File in $Files) {
    Write-Progress -Activity "Processing" -Status "$($File.Name)" -PercentComplete (($Completed/$Files.Length)*100)

    #Load CKL
    $CKLData = Import-StigCKL -Path $File.FullName
    #Load results
    $Results = Get-VulnCheckResult -CKLData $CKLData
    #Grab non-revieweds
    $NR= @()+($Results | Where-Object {$_.Status -eq "Not_Reviewed"})

    $Report = ""
    foreach($Item in $NR) {
        $Report+=$Item.VulnID+"; "
    }
    if ($Report -ne "") {
        $FormattedData+=New-Object -TypeName PSObject -Property @{File=$File.FullName; NotReviewed = $Report}
    }
    #Increment Progress
    $Completed++;
}

$FormattedData | Export-Csv -Path $SavePath -NoTypeInformation
Write-Progress -Activity "Processing" -Completed