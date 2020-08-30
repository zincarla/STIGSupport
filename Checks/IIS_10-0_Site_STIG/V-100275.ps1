Param($BeginData)
Write-Verbose "V-100275"

$Result = "NotAFinding"
$Details = ""
$Comments = ""

Import-Module WebAdministration;
$Pools = (Get-ChildItem -PSPath "IIS:\AppPools")
$CheckResult = @()
foreach ($Pool in $Pools)
{
    $CheckResult += New-Object -TypeName PSObject -Property @{Name=$Pool.Name;RapidFail=$Pool.failure.rapidFailProtection}
}

if ($CheckResult -ne $null -and $CheckResult.Length -gt 0)
{
    foreach ($Pool in $CheckResult)
    {
        if ($Pool.RapidFail -ne $true)
        {
            $Result="Open"
            $Details+=$Pool.Name+" : "+$Pool.RapidFail.ToString()+"`r`n"
        } else {
            $Comments+=$Pool.Name+" : "+$Pool.RapidFail.ToString()+"`r`n"            
        }
    }
} else {
    $Result="Not_Reviewed"
    $Details+="Web config could not be queried. "
}

return @{Details=$Details;
            Comments=$Comments;
            Result=$Result}