<#
.SYNOPSIS
    Grabs metrics per service for multiple checklists

.DESCRIPTION
    Generates high-level metrics on checklist by service. Note that your directory must be in a specific format. All checklists located in a child of the parent folder are counted as one service

.PARAMETER CKLDirectoryPath
    Parent of the service directories. Example structure
        Parent
            |-IIS
            |-OS
            |-Some other Service

.PARAMETER SavePath
    Location to save the output csv files containing the metrics.

.PARAMETER SavePathSavePath
    Path to save the CSV Files

.OUTPUT
    One CSV file for each subfolder of $CKLDirectoryPath. Each CSV is intended to represent one service.

.EXAMPLE
    Export-MetricsReport.ps1 -CKLDirectoryPath C:\CKLs -SavePath C:\Reports
#>
Param([Parameter(Mandatory=$true)]$CKLDirectoryPath, [Parameter(Mandatory=$true)]$SavePath)
#Check if module imported
if ((Get-Module|Where-Object -FilterScript {$_.Name -eq "StigSupport"}).Count -le 0)
{
    #End if not
    Write-Error "Please import StigSupport.psm1 before running this script"
    return
}

$Services = Get-ChildItem -Path $CKLDirectoryPath -Directory

Write-Progress -Activity "Processing" -PercentComplete 0
$Completed =0
#Loop through each of the CKL directories, remember each should be named after the service they are for (IIS, Windows OS, etc)
foreach ($Service in $Services) {
    Write-Progress -Activity "Processing" -PercentComplete (($Completed/$Services.Length)*100)
    $Metrics = Get-StigMetrics -CKLDirectory $Service.FullName
    $FormattedData = @()

    foreach ($Cat in $Metrics.CategoryScores.Keys) {
        #Reformat the data in a CSV friendly way
        $FormattedData += New-Object -TypeName PSObject -Property @{
                                                                    Category=$Cat;
                                                                    Open=$Metrics.CategoryScores[$Cat].Open;
                                                                    Total=$Metrics.CategoryScores[$Cat].Total;
                                                                    NotAFinding=$Metrics.CategoryScores[$Cat].NotAFinding;
                                                                    UniqueTotal=$Metrics.CategoryScores[$Cat].UniqueTotal;
                                                                    NotApplicable=$Metrics.CategoryScores[$Cat].NotApplicable;
                                                                    NotReviewed=$Metrics.CategoryScores[$Cat].NotReviewed;
                                                                }
    }
    #Export the metrics
    $FormattedData | Export-Csv -Path (Join-Path -Path $SavePath -ChildPath ($Service.Name+".csv")) -NoTypeInformation
    #Increment Progress
    $Completed++;
}
Write-Progress -Activity "Processing" -Completed