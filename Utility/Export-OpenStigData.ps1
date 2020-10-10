<#
.SYNOPSIS
    Saves a CSV containing information on all Open stigs

.DESCRIPTION
    Saves a CSV containing information on all Open stigs

.PARAMETER CKLDirectory
    Full path to a directory containing your checklists

.PARAMETER SavePath
    Full path to save the report to, including file name

.PARAMETER SeperateDuplicates
    Instead of adding duplicate assets for a stig on one line, this will add a new line for each asset affected by a STIG
  
.EXAMPLE
    "Export-OpenStigData.ps1" -CKLDirectory 'C:\CKLs\' -SavePath 'C:\CKLs\OpenChecks.csv'
#>
Param([Parameter(Mandatory=$true)]$CKLDirectory,[Parameter(Mandatory=$true)]$SavePath,[switch]$SeperateDuplicates,[switch]$Recurse)
#Check if module imported
if ((Get-Module|Where-Object -FilterScript {$_.Name -eq "StigSupport"}).Count -le 0)
{
    #End if not
    Write-Error "Please import StigSupport.psm1 before running this script"
    return
}

#List all CKL Files
$CKLs = Get-ChildItem -Path $CKLDirectory -Filter "*.ckl" -Recurse:$Recurse

#Initialize Results
$STIGData = @()
Write-Progress -Activity "Processing CKLs" -PercentComplete 0
#To keep track of progress
$I=0
foreach ($CKL in $CKLs)
{
    #Load this CKL
    $CKLData = Import-StigCKL -Path $CKL.FullName
    $HostData = Get-CKLHostData -CKLData $CKLData
    #Grab data on all stigs.
    #Format of @{Status,Finding,Comments,VulnID}
    $Stigs = Get-VulnCheckResult -XMLData $CKLData
    $Asset = $HostData.HostName
    foreach ($Stig in $Stigs)
    {
        #Requested STIG, Vuln ID, Rule Title/Name, Check Content, Fix Text
        if ($Stig.Status -eq "Open" -or $Stig.Status -eq "Not_Reviewed" -or $Stig.Status -eq $null) {
            Write-Host "Need $($Stig.VulnID)"
            if (-not $SeperateDuplicates -and ($STIGData | Where-Object -FilterScript {$_.VulnID -eq $Stig.VulnID})) {
                #If we have already have an instance of this vuln, then increment the count of open instances of it
                ($STIGData | Where-Object -FilterScript {$_.VulnID -eq $Stig.VulnID}).Count++;
                #Add asset name to it
                ($STIGData | Where-Object -FilterScript {$_.VulnID -eq $Stig.VulnID}).Asset+=", $Asset";
            } else {
                #If this is the first instance of this stig, or if user specified new rows for each asset, create a new result object and add it to the array
                $ToAdd = New-Object -TypeName PSObject -Property @{Asset="$Asset";STIG="";VulnID=$Stig.VulnID;RuleTitle="";CheckContent="";FixText="";Count=1}
                $ToAdd.STIG = Get-StigInfoAttribute -XMLData $CKLData -Attribute "title"
                $ToAdd.RuleTitle = Get-VulnInfoAttribute -XMLData $CKLData -VulnID $Stig.VulnID -Attribute "Rule_Title"
                $ToAdd.CheckContent = Get-VulnInfoAttribute -XMLData $CKLData -VulnID $Stig.VulnID -Attribute "Check_Content"
                $ToAdd.FixText = Get-VulnInfoAttribute -XMLData $CKLData -VulnID $Stig.VulnID -Attribute "Fix_Text"
                $STIGData += $ToAdd
            }
        } else {
            #If not open or NR
            Write-Host "Skip $($Stig.VulnID)"
        }
    }
    $I++
    Write-Progress -Activity "Processing CKLs" -PercentComplete (($I/$CKLs.Length)*100)
}
Write-Progress -Activity "Saving Report" -PercentComplete 99
$STIGData | Export-Csv -Path $SavePath -NoTypeInformation
Write-Progress -Activity "Saving Report" -PercentComplete 100 -Completed
