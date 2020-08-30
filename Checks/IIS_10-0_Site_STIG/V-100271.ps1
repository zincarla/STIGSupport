Param($BeginData)
Write-Verbose "V-100271"

$Result = "NotAFinding"
$Details = ""
$Comments = ""

Import-Module WebAdministration;
$Pools = (Get-ChildItem -PSPath "IIS:\AppPools")
$CheckResult = @()
foreach ($Pool in $Pools)
{
    $CheckResult += New-Object -TypeName PSObject -Property @{Name=$Pool.Name;Periodic=$Pool.recycling.periodicRestart.time.TotalMilliseconds;Regular=$Pool.recycling.periodicRestart.schedule.Collection.Length}
}

if ($CheckResult -ne $null -and $CheckResult.Length -gt 0)
{
    foreach ($Pool in $CheckResult)
    {
        if ($Pool.Periodic -eq 0 -or $Pool.Regular -eq 0)
        {
            $Result="Open"
            $Details+=$Pool.Name+" : `r`n`tPeriodic: "+$Pool.Periodic.ToString()+"`r`n`tRegular: "+$Pool.Regular.ToString()+"`r`n"
        } else {
            $Comments+=$Pool.Name+" : `r`n`tPeriodic: "+$Pool.Periodic.ToString()+"`r`n`tRegular: "+$Pool.Regular.ToString()+"`r`n"            
        }
    }
} else {
    $Result="Not_Reviewed"
    $Details+="Web config could not be queried. "
}

return @{Details=$Details;
            Comments=$Comments;
            Result=$Result}