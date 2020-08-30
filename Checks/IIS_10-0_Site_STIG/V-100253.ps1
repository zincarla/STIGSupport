Param($BeginData)
Write-Verbose "V-100253"

$Result = "NotAFinding"
$Details = ""
$Comments = ""

Import-Module WebAdministration
$Bindings =(Get-Item -PSPath "IIS:\Sites\$($BeginData.Site)").bindings.collection

if ($Bindings -ne $null)
{
    foreach ($Binding in $Bindings)
    {
        if ($Binding.Protocol -ne "http" -and $Binding.Protocol -ne "https") {
            $Result = "Not_Reviewed"
            $Details+=$Binding.Protocol+"/"+$Binding.bindingInformation+" requires manual review`r`n"
        } elseif ($Binding.Protocol -eq "http" -and $Binding.bindingInformation -notmatch "^.*:?(80):?.*$"){
            $Result = "Not_Reviewed"
            $Details+=$Binding.Protocol+"/"+$Binding.bindingInformation+" requires manual review`r`n"
        } elseif ($Binding.Protocol -eq "https" -and $Binding.bindingInformation -notmatch "^.*:?(443):?.*$"){
            $Result = "Not_Reviewed"
            $Details+=$Binding.Protocol+"/"+$Binding.bindingInformation+" requires manual review`r`n"
        } else {
            $Comments += $Binding.Protocol+"/"+$Binding.bindingInformation+" is a known port/protocol`r`n"
        }
    }
} else {
    $Result="Not_Reviewed"
    $Details+="Web config could not be queried. "
}

return @{Details=$Details;
            Comments=$Comments;
            Result=$Result}