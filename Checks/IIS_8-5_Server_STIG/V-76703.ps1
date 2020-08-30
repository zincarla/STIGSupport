Write-Verbose "V-100123"
$Result = "NotAFinding"
$Details = ""
$Comments = ""

Import-Module WebAdministration

$Modules = @()
Get-WebManagedModule | ForEach-Object -Process {$Modules += $_.Name}
Get-WebGlobalModule | ForEach-Object -Process {$Modules += $_.Name}

if ($Modules -ne $null -and $Modules.Length -gt 0)
{
    #TODO: Verify this module name, otherwise may always be open!
    if ($Modules.Contains("ApplicationRequestRoutingCache"))
    {
        $Result = "Not_Reviewed"
        $Comments+="ApplicationRequestRoutingCache is installed`r`n"
        #TODO: Actually check proxy setting
    } else {
        $Details+="ApplicationRequestRoutingCache not installed. "
    }
    foreach ($M in $Modules){$Comments+=$M+". "}
} else {
    $Result="Not_Reviewed"
    $Details+="Modules could not be enumerated. "
}

return @{Details=$Details;
            Comments=$Comments;
            Result=$Result}