<#
.SYNOPSIS
    Sets all NotReviewed in a CKLB to Open

.DESCRIPTION
    Loads a CKLB, and sets all not_reviewed to open, then saves it

.PARAMETER CKLPath
    Full path to the CKLB file
  
.EXAMPLE
    "Set-NRtoOpen.ps1" -CKLBPath 'C:\CKLs\MyChecklist.cklb'
#>
Param([Parameter(Mandatory=$true)][ValidateScript({Test-Path -Path $_})][string]$CKLBPath)

#Check if module imported
if ((Get-Module|Where-Object -FilterScript {$_.Name -eq "StigSupport"}).Count -le 0)
{
    #End if not
    Write-Error "Please import StigSupport.psm1 before running this script"
    return
}

#If pointing to a single CKL, set children to an array that only contains that one ckl
if ($CKLBPath.EndsWith(".cklb"))
{
    $Children = @($CKLBPath)
}
else
{
    #Otherwise, load all CKL files from that path and put it into an array
    $Files = Get-ChildItem -Path $CKLBPath -Filter "*.CKLB"
    $Children = @()
    foreach ($File in $Files)
    {
        $Children += $File.FullName
    }
    if ($Children.Length -eq 0)
    {
        Write-Error "No CKLB files found in directory"
        return
    }
}

$I=0
Write-Progress -Activity "Setting CKLBs" -PercentComplete (($I*100)/$Children.Length) -Id 1
#Loop through the CKL Files
foreach ($Child in $Children)
{
    $Name = $Child.Split("\")
    $Name = $Name[$Name.Length-1]
    Write-Progress -Activity "Setting CKLBs" -PercentComplete (($I*100)/$Children.Length) -Id 1
    #Load the CKL file
    $CKLBData = Import-StigCKLBFile -Path $Child
    Write-Progress -Activity "$Name" -Status "Loading Stigs" -PercentComplete 0 -Id 2
    #Load the stig results from the CKL
    $Stigs = Get-StigCKLBRuleInfo -CKLBData $CKLBData -All
    #For each stig, that is "not_reviewed", set it to open
    Write-Progress -Activity "$Name" -Status "Starting Loop" -PercentComplete (($I*100)/$Children.Length) -Id 2
    $S =0
    foreach ($Stig in $Stigs)
    {
        Write-Progress -Activity "$Name" -Status "$($Stig.group_id)" -PercentComplete (($S*100)/$Stigs.Length) -Id 2
        if ($Stig.Status -eq "not_reviewed" -or $Stig.Status -eq "NotReviewed")
        {
            Write-Host "$($Stig.group_id) is being marked open"
            Set-StigCKLBRuleFinding -CKLBData $CKLBData -VulnID $Stig.group_id -Result open
        }
        $S++
    }
    #Save the ckl
    Export-StigCKLBFile -CKLBData $CKLBData -Path $Child
    Write-Progress -Activity "$Name" -Status "Complete" -PercentComplete 100 -Id 2 -Completed
    $I++
}
Write-Progress -Activity "Setting CKLs" -PercentComplete 100 -Id 1 -Completed