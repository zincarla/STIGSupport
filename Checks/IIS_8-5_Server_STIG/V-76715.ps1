Write-Verbose "V-100135"
$Result = "NotAFinding"
$Details = ""
$Comments = ""

$Certs = Get-ChildItem -Path cert:\LocalMachine\My, cert:\LocalMachine\WebHosting -SSLServerAuthentication

if ($Certs -eq $null)
{
    $Result = "Open"
    $Details = "No SSL certificates found. "
} else {
    foreach ($Cert in $Certs)
    {
        #TODO/NOTE: Technically this only checks if the issuer looks like a DoD cert. It does not actually validate that it is one.
        if (($Cert.Issuer -match "CN=DOD.*CA-\d{1,4}.*"))
        {
            $Comments += "'$($Cert.FriendlyName)' is signed by $($Cert.Issuer) which appears to be a DOD CA. "
        }
        else {
            #Not directly signed by a CA, so see if chains to a root
            $CertChain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain
            $null=$CertChain.Build($Cert)
            $Root= $CertChain.ChainElements[$CertChain.ChainElements.Count-1].Certificate
            if ($Root.Issuer -match "CN=DOD.*CA-\d{1,4}.*") {
                $Comments += "'$($Cert.FriendlyName)' chains to $($Root.Issuer). "
            } else {
                $Details += "'$($Cert.FriendlyName)' is signed by $($Cert.Issuer) and does not seem to chain to a DOD Root. "
                $Result = "Open"
            }
        }
    }
}

return @{Details=$Details;
            Comments=$Comments;
            Result=$Result}