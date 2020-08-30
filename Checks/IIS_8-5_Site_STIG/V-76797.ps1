Param($BeginData)
Write-Verbose "V-100207"

$Result = "NotAFinding"
$Details = ""
$Comments = ""

Import-Module WebAdministration
$MIME =(Get-WebConfigurationProperty "system.webServer/staticContent" -Name collection -PSPath "IIS:\Sites\$($BeginData.Site)").fileextension

$Bad = @(".exe", ".dll",".com",".bat",".csh")

if ($MIME -ne $null)
{
    foreach ($M in $MIME)
    {
        if ($Bad.Contains($M))
        {
            $Details+="$M was found against STIG. "
            $Result = "Open"
        }
    }
} else {
    $Result="Not_Reviewed"
    $Details+="MIMEs could not be enumerated. "
}

return @{Details=$Details;
            Comments=$Comments;
            Result=$Result}