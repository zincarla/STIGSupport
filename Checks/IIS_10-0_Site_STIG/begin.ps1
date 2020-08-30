Param($InitObject)
$Applicable = $true;
$FeatureData = Get-WindowsFeature web-server -ErrorAction SilentlyContinue
if ($FeatureData -ne $null -and $FeatureData.InstallState -ne $null -and $FeatureData.InstallState -ne "Installed") {
    $Applicable = $false; #Missing IIS Feature
}
Import-Module WebAdministration
if ($InitObject -eq $null -or $InitObject -eq "" -or -not (Test-Path -Path "IIS:\Sites\$InitObject")) {
    $Applicable = $false #Target site does not exist
}

return @{IsApplicable=$Applicable;Site=$InitObject}