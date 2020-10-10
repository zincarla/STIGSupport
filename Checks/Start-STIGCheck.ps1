<#
.SYNOPSIS
    Scans a specified machine using scripts provided in the checks folder specified. Sort of like SCAP but with PowerShell and saves directly to the CKL format.

.PARAMETER MachineName
    The machine to scan for STIG results

.PARAMETER CKL
    The CKL file that needs to be filled

.PARAMETER CheckDirectory
    Path to where the STIG check scripts are stored, usually .\STIGSUPPORT\Checks
  
.PARAMETER SavePath
    Full path to save the filled CKL to, if specified this will not overwrite CKL, if not, CKL will be overwritten by default

.PARAMETER InitObject
    A check-specific initialization object, maybe a site in IIS, or other variable that cannot be automatically determined by the checks

.PARAMETER SkipChecks
    An array of checks to skip, usefull if you need to skip checks that take an exceptionally long time
  
.EXAMPLE
    Merge-CKLs -DestinationCKLFile "C:\CKLS\Blank.ckl" -DestinationCKLFile "C:\CKLS\Answered.ckl" -SaveFilePath "C:\CKLS\Merged.ckl"

.EXAMPLE
    Merge-CKLs -DestinationCKLFile "C:\CKLS\ManualChecks.ckl" -DestinationCKLFile "C:\CKLS\ScapResults.ckl" -SaveFilePath "C:\CKLS\MergedChecks.ckl" -DontCopyHostInfo -DontOverwriteVulns

.EXAMPLE
    Merge-CKLs -DestinationCKLFile "C:\CKLS\Blank.ckl" -DestinationCKLFile "C:\CKLS\Answered.ckl" -SaveFilePath "C:\CKLS\Merged.ckl" -IncludeNR

.EXAMPLE
    Merge-CKLs -DestinationCKLFile "C:\CKLS\Blank.ckl" -DestinationCKLFile "C:\CKLS\Answered.ckl" -SaveFilePath "C:\CKLS\Merged.ckl" -SkipChecks @("V-123456","V-123457")
#>
Param($MachineName="localhost",[Parameter(Mandatory=$true)]$CKL,[Parameter(Mandatory=$true)]$CheckDirectory,$SavePath=$CKL,$InitObject=$null,$SkipChecks)

#Metrics
$StartTime = Get-Date

#Ensure we have pre-req module imported
if ((Get-Module|Where-Object -FilterScript {$_.Name -eq "StigSupport"}).Count -le 0) {
    Write-Error "Please import StigSupport.psm1 before running this script"
    exit 1
}

#Check if we have a set of checks for the CKL
$CKLData = Import-StigCKL -Path $CKL
$CKLMetadata = Get-CheckListInfo -CKLData $CKLData
$StigDir = Join-Path -Path $CheckDirectory -ChildPath $($CKLMetadata.ID)
if (-not (Test-Path $StigDir)) {
    Write-Error "No checks exist for $($CKLMetadata.ID)"
    return
}

#Ensure SkipChecks is an array
if ($SkipChecks -ne $null) {
    $SkipChecks = @()+$SkipChecks
} else {
    $SkipChecks = @()
}

$Session = New-PSSession -ComputerName $MachineName -EnableNetworkAccess

if (-not $Session) {
    Write-Host "-=Metrics=-"
    Write-Host "This script cancelled in $(((Get-Date) - $StartTime).TotalMinutes) minutes"
    return
}

#Add host data
$FQDN = $MachineName
if (-not $MachineName.Contains(".")) {
    $FQDN = $MachineName+"."+$env:USERDNSDOMAIN
}
$IP = (@()+(Resolve-DnsName -Name $MachineName -Type A).IPAddress)[0]
$Mac = Invoke-Command -Session $Session -ScriptBlock {(@()+(Get-NetAdapter | Where-Object {$_.Status -eq "Up" -and $_.Name.Contains("Ethernet")}).MacAddress)[0]}
Set-CKLHostData -CKLData $CKLData -Host $MachineName -AutoFill

#Start with Begin.ps1
$BeginData = $null
if (Test-Path (Join-Path -Path $StigDir -ChildPath "begin.ps1")) {
    Write-Host "Running begin.ps1"
    $CheckTime = Get-Date
    $BeginData = Invoke-Command -Session $Session -FilePath (Join-Path -Path $StigDir -ChildPath "begin.ps1") -ArgumentList @($InitObject)
    Write-Verbose "begin.ps1 took $(((Get-Date)-$CheckTime).TotalSeconds) seconds to complete"
    if ($BeginData.IsApplicable -eq $false) {
        Write-Host "The begin.ps1 script says that $($CKLMetadata.ID) is not applicable to $MachineName"
        return
    }
    Write-Verbose ($BeginData|Out-String)
}

#Run through the checks
$Checks = Get-ChildItem -Path $StigDir -Filter "*.ps1" -File | Where-Object {$_.Name -ne "begin.ps1" -and $_.Name -ne "end.ps1"} #In PS 6.1 this would be easier
$ValidResults = @("Open", "NotAFinding","Not_Reviewed","Not_Applicable")
$QuickConversions = @{"NotReviewed"="Not_Reviewed";"NR"="Not_Reviewed";"NotApplicable"="Not_Applicable";"NA"="Not_Applicable";"O"="Open";"Closed"="NotAFinding"}
foreach ($Check in $Checks) {
    if ($SkipChecks -contains $Check.Name -or ($Check.Name.Length -gt 4 -and $SkipChecks -contains ($Check.Name.Substring(0,$Check.Name.Length-4)))){
        Write-Host "Skipping $($Check.Name)"
        continue
    }
    Write-Host "Running $($Check.Name)"
    $CheckTime = Get-Date
    $Result = Invoke-Command -Session $Session -FilePath $Check.FullName -ArgumentList @($BeginData)
    Write-Verbose "$($Check.Name) took $(((Get-Date)-$CheckTime).TotalSeconds) seconds to complete"
    $Details = $Result.Details
    $Comments = $Result.Comments
    $CheckResult = $Result.Result
    $CheckName = $Check.Name -replace "\.ps1",""
    #Helper to convert some quick typos
    if ($QuickConversions.ContainsKey($CheckResult)) {
        Write-Verbose "Result '$CheckResult' for $($Check.Name) will be corrected to $($QuickConversions[$CheckResult])"
        $CheckResult = $QuickConversions[$CheckResult]
    }
    #Validate result
    if (-not $ValidResults.Contains($CheckResult)) {
        $CheckResult = "Not_Reviewed"
        Write-Warning "Invalid result '$CheckResult' for $($Check.Name). This has been set to Not_Reviewed"
    }
    Set-VulnCheckResult -CKLData $CKLData -VulnID $CheckName -Details $Details -Comments $Comments -Result $CheckResult
}


#End with End.ps1
if (Test-Path (Join-Path -Path $StigDir -ChildPath "end.ps1")) {
    Write-Host "Running end.ps1"
    $CheckTime = Get-Date
    Invoke-Command -Session $Session -FilePath (Join-Path -Path $StigDir -ChildPath "end.ps1") -ArgumentList @($BeginData)
    Write-Verbose "end.ps1 took $(((Get-Date)-$CheckTime).TotalSeconds) seconds to complete"
}

#Finalize
Remove-PSSession -Session $Session
Export-StigCKL -CKLData $CKLData -Path $SavePath

Write-Host "-=Metrics=-"
Write-Host "This script took $(((Get-Date) - $StartTime).TotalMinutes) minutes to complete"
