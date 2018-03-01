<#
.SYNOPSIS
    Script will run through a target directory and build a collection of CKL files. From there it will parse them and find all checks that are set to Open or Not Reviewed and add each
    to an object. End result is a CSV file that can be used to copy and pasted bulk POA&M data into a provided template.

.DESCRIPTION
    Same as synopsis

.PARAMETER CKLDirectory
    Directory that serves as the "root" to be searched for CKL files

.PARAMETER SavePath
    Directory and filename for desired CSV output

.EXAMPLE
    Generate-POAM -CKLDirectory <path to desired CKLs> -SavePath <Desired path and filename.csv>
#>
Param(
    [parameter(Mandatory=$true)]$CKLDirectory,
    [parameter(Mandatory=$true)]$SavePath,
    [int]$DaysOut=120
)
#New Comment
class POAMItem {
    [string]$RuleTitle
    [string]$Category
    [string]$VulnID
    [string]$STIGID
    [string]$POAM
    [string]$Source
    [string]$Resources
    [string]$TgtDate
    [string]$AssetName
    [string]$STIG
    #[int]$Count
}


$CKLs = @()
$STIGData = @()

if ((Get-Module|Where-Object -FilterScript {$_.Name -eq "StigSupport"}).Count -le 0)
{
    #End if not
    Write-Error "Please import StigSupport.psm1 before running this script"
    return
}

$CKLs = (Get-ChildItem -Recurse -Path $CKLDirectory -Filter "*.ckl" -ErrorAction SilentlyContinue)

foreach($CKL in $CKLs) {
    #Load the CKL
    $CKLData = Import-StigCKL -Path $CKL.FullName
    $HostData = Get-CKLHostData -CKLData $CKLData
    #Grab data from current CKL and import as STIG items
    #Format into useable objects for POAM generation
    $STIGs = Get-VulnCheckResult -XMLData $CKLData
    $Asset = $HostData.HostName
    foreach($STIG in $STIGs) {
        if($STIG.Status -eq "Open" -or $STIG.Status -eq "Not_Reviewed" -or $STIG.Status -eq $null) {
            Write-Host "$STIG.VulnID is Identified as non-compliant"
            $tempDate = (Get-Date).AddDays($DaysOut).ToFileTime()
            $tgtDate = [datetime]::FromFileTime($tempDate).ToString('MM/d/y')
            $ToAdd = New-Object POAMItem -Property @{RuleTitle="";Category="";VulnID=$STIG.VulnID;STIGID="";POAM="POA&M";Source="Manual Inspection";Resources="";TgtDate="";AssetName="";STIG=""}
            $ToAdd.RuleTitle = Get-VulnInfoAttribute -XMLData $CKLData -VulnID $STIG.VulnID -Attribute "Rule_Title"
            $Severity = Get-VulnInfoAttribute -XMLData $CKLData -VulnID $STIG.VulnID -Attribute Severity
            if($Severity -eq "low") {
                $Cat = "CAT III"
            } elseif ($Severity -eq "medium") {
                $Cat = "CAT II"
            } elseif ($Severity -eq "high" -or $Severity -eq "critical") {
                $Cat = "CAT I"
            }
            $ToAdd.Category = $Cat
            $ToAdd.STIGID = Get-VulnInfoAttribute -XMLData $CKLData -VulnID $STIG.VulnID -Attribute "Rule_Ver"
            $ToAdd.TgtDate = $tgtDate
            $ToAdd.AssetName = $Asset
            $ToAdd.STIG = Get-StigInfoAttribute -CKLData $CKLData -Attribute "stigid"
            $STIGData += $ToAdd
        } else {
            Write-Host "Skipping $($STIG.VulnID)"
        }
    }
}

$STIGData | Export-Csv -Path $SavePath -NoTypeInformation