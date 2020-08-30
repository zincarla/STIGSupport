$Applicable = $true;
$FeatureData = Get-WindowsFeature web-server -ErrorAction SilentlyContinue
if ($FeatureData -ne $null -and $FeatureData.InstallState -ne $null -and $FeatureData.InstallState -ne "Installed") {
    $Applicable = $false;
    Write-Host "IIS Feature does not appear to be installed."
}
return @{IsApplicable=$Applicable;}