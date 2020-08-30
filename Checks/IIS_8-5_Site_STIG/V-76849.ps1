Param($BeginData)
Write-Verbose "V-100255"

$Result = "NotAFinding"
$Details = ""
$Comments = ""

Import-Module WebAdministration
$Bindings = (Get-Item -PSPath "IIS:\Sites\$($BeginData.Site)").bindings.collection
$HTTPSBindings = @()+($Bindings | Where-Object{$_.Protocol -eq "https"})


if ($Bindings -ne $null)
{
    if ($HTTPSBindings -ne $null) {
        foreach ($Binding in $HTTPSBindings)
        {
            if ($Binding.certificateHash -eq $null -or $Binding.certificateHash -eq "") {
                $Result="Open"
                $Details+=$Binding.Protocol+"/"+$Binding.bindingInformation+" does not have a cert`r`n"
            } else {
                $Cert = Get-Item -Path "cert:\LocalMachine\$($Binding.certificateStoreName)\$($Binding.certificateHash)"
                if ($Cert -ne $null) {
                    #Ok, by this point, we filtered to https, ensured the cert exists, and saved it to a variable
                    #Now we need to check if signed by DOD cert
                    #TODO/NOTE: Technically this only checks if the issuer looks like a DoD cert. It does not actually validate that it is one.
                    if (($Cert.Issuer -match "CN=DOD.*CA-\d{1,4}.*"))
                    {
                        $Comments += $Binding.Protocol+"/"+$Binding.bindingInformation+" is set to use '$($Cert.FriendlyName)' and is signed by $($Cert.Issuer) which appears to be a DOD CA.`r`n"
                    } else {
                        #Not directly signed by a CA, so see if chains to a root
                        $CertChain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain
                        $null=$CertChain.Build($Cert)
                        $Root= $CertChain.ChainElements[$CertChain.ChainElements.Count-1].Certificate
                        if ($Root.Issuer -match "CN=DOD.*CA-\d{1,4}.*") {
                            $Comments += $Binding.Protocol+"/"+$Binding.bindingInformation+" is set to use '$($Cert.FriendlyName)' and is signed by $($Cert.Issuer) which chains to a DOD CA.`r`n"
                        } else {
                            $Details += $Binding.Protocol+"/"+$Binding.bindingInformation+" is set to use '$($Cert.FriendlyName)' and is signed by $($Cert.Issuer) which does not seem to chain to a DOD CA.`r`n"
                            $Result = "Open"
                        }
                    }
                } else {
                    if ($Result -ne "Open") {
                        $Result="Not_Reviewed"
                    }
                    $Details+=$Binding.Protocol+"/"+$Binding.bindingInformation+" could not retrieve cert from cert store, manual review required`r`n"
                }
            }
        }
    } else {
        $Result="Open"
        $Details+="HTTPS Binding not found. "
    }
} else {
    $Result="Not_Reviewed"
    $Details+="Web config could not be queried. "
}

return @{Details=$Details;
            Comments=$Comments;
            Result=$Result}