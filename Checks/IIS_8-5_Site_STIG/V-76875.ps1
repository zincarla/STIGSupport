Param($BeginData)
Write-Verbose "V-76875"

$Result = "NotAFinding"
$Details = ""
$Comments = ""

Import-Module WebAdministration;
$Pools = (Get-ChildItem -PSPath "IIS:\AppPools")
$CheckResult = @()
foreach ($Pool in $Pools)
{
    $CheckResult += New-Object -TypeName PSObject -Property @{Name=$Pool.Name;Que=$Pool.queueLength}
}

if ($CheckResult -ne $null -and $CheckResult.Length -gt 0)
{
    foreach ($Pool in $CheckResult)
    {
        if ($Pool.Que -gt 1000)
        {
            $Result="Open"
            $Details+=$Pool.Name+" : "+$Pool.Que.ToString()+"`r`n"
        } else {
            $Comments+=$Pool.Name+" : "+$Pool.Que.ToString()+"`r`n"
        }
    }
} else {
    $Result="Not_Reviewed"
    $Details+="Web config could not be queried. "
}

return @{Details=$Details;
            Comments=$Comments;
            Result=$Result}