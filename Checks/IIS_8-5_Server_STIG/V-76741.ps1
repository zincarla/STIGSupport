Write-Verbose "V-100159"
$Result = "NotAFinding"
$Details = ""
$Comments = ""

$Check = (Get-WindowsFeature -Name Web-Mgmt-Service).Installed

if ($Check -ne $null) {
    if (-not $Check) {
        $Result = "Not_Applicable"
        $Details="Remote management not installed"
    } else {
        $Result = "Not_Reviewed"
        $Details="Remote management is installed, manual check required to verify ip range restrictions"
    }
} else {
    $Result="Not_Reviewed"
    $Details+="Windows feature could not be queried. "
}

return @{Details=$Details;
            Comments=$Comments;
            Result=$Result}