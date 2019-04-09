Param($MachineName="localhost",[Parameter(Mandatory=$true)]$CKL,[Parameter(Mandatory=$true)]$CheckDirectory,$SavePath=$CKL)

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

$Session = New-PSSession -ComputerName $MachineName -EnableNetworkAccess

#Add host data
$FQDN = $MachineName
if (-not $MachineName.Contains(".")) {
    $FQDN = $MachineName+"."+$env:USERDNSDOMAIN
}
$IP = (@()+(Resolve-DnsName -Name $MachineName -Type A).IPAddress)[0]
$Mac = Invoke-Command -Session $Session -ScriptBlock {(@()+(Get-NetAdapter | Where-Object {$_.Status -eq "Up" -and $_.Name.Contains("Ethernet")}).MacAddress)[0]}
Set-CKLHostData -CKLData $CKLData -Host $MachineName -FQDN $FQDN -IP $IP -Mac $Mac

#Start with Begin.ps1
$BeginData = $null
if (Test-Path (Join-Path -Path $StigDir -ChildPath "begin.ps1")) {
    Write-Host "Running begin.ps1"
    $CheckTime = Get-Date
    $BeginData = Invoke-Command -Session $Session -FilePath (Join-Path -Path $StigDir -ChildPath "begin.ps1")
    Write-Verbose "begin.ps1 took $(((Get-Date)-$CheckTime).TotalSeconds) seconds to complete"
    if ($BeginData.IsApplicable -eq $false) {
        Write-Host "The begin.ps1 script says that $($CKLMetadata.ID) is not applicable to $MachineName"
        return
    }
}

#Run through the checks
$Checks = Get-ChildItem -Path $StigDir -Filter "*.ps1" -File | Where-Object {$_.Name -ne "begin.ps1" -and $_.Name -ne "end.ps1"} #In PS 6.1 this would be easier
$ValidResults = @("Open", "NotAFinding","Not_Reviewed","Not_Applicable")
$QuickConversions = @{"NotReviewed"="Not_Reviewed";"NR"="Not_Reviewed";"NotApplicable"="Not_Applicable";"NA"="Not_Applicable";"O"="Open";"Closed"="NotAFinding"}
foreach ($Check in $Checks) {
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