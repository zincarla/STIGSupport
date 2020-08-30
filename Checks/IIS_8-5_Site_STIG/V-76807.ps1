Param($BeginData)
Write-Verbose "V-100217"

$Result = "NotAFinding"
$Details = ""
$Comments = ""

Import-Module WebAdministration
$Bindings =(Get-Item -PSPath "IIS:\Sites\$($BeginData.Site)").bindings.collection | Where-Object {$_.Protocol -eq "http" -or $_.Protocol -eq "https"}

if ($Bindings -ne $null)
{
    foreach ($Binding in $Bindings)
    {
        if ($Binding.bindingInformation -notmatch "^[^\*]+:(443|80):[^\*]+$") { 
            $Result = "Open"
            $Details+=$Binding.bindingInformation+" appears to be incorrect`r`n"
        } else {
            $Comments += $Binding.bindingInformation+" appears to be correct`r`n"
        }
    }
} else {
    $Result="Not_Reviewed"
    $Details+="Bindings could not be enumerated. "
}

return @{Details=$Details;
            Comments=$Comments;
            Result=$Result}