Param($BeginData)
Write-Verbose "V-100213"

$Result = "NotAFinding"
$Details = ""
$Comments = ""

Import-Module WebAdministration

$Modules = @()
Get-WebManagedModule -PSPath "IIS:\Sites\$($BeginData.Site)" | ForEach-Object -Process {$Modules += $_.Name}
Get-WebGlobalModule | ForEach-Object -Process {$Modules += $_.Name}

if ($Modules -ne $null -and $Modules.Length -gt 0)
{
    #TODO: Validate module name
    if ($Modules.Contains("WebDAVAuthoringRules"))
    {
        $Result = "Open"
        $Details = "WebDAVAuthoringRules found."
    }
    foreach ($M in $Modules){$Comments+=$M+". "}
} else {
    $Result="Not_Reviewed"
    $Details+="Modules could not be enumerated. "
}

return @{Details=$Details;
            Comments=$Comments;
            Result=$Result}