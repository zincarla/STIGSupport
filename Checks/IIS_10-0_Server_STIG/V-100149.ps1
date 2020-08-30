Write-Verbose "V-100145"
$Result = "NotAFinding"
$Details = ""
$Comments = ""

Import-Module WebAdministration;
$Settings = (New-Object -TypeName PSObject -Property @{Validation=(Get-WebConfigurationProperty "//machineKey" -Name "validation");EncryptionMethod=(Get-WebConfigurationProperty "//machineKey" -Name "decryption").value}) #It is called decryption, dunno why

if ($Settings -ne $null)
{
    $Details = "Validation is set to $($Settings.Validation)`r`nEncryptionMethod is set to $($Settings.EncryptionMethod)"

    if ($Settings.Validation -ne "HMACSHA256" -and $Settings.Validation -ne "HMACSHA386" -and $Settings.Validation -ne "HMACSHA512" -and $Settings.Validation -ne "AES")
    {
        $Result="Open"
    }
    if ($Settings.EncryptionMethod -ne "Auto")
    {
        $Result="Open"
    }

} else {
    $Result="Not_Reviewed"
    $Details+="Web config properties could not be queried. "
}

return @{Details=$Details;
            Comments=$Comments;
            Result=$Result}