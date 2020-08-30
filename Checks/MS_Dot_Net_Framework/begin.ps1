#Gather all .exe.config files for processing in script
Write-Host "Caching *.exe.config files and machine.config files. This will take time."
$EXEConfigFiles = @()
$Drives = Get-Volume | Where-Object {$_.DriveLetter -ne $null -and $_.DriveType -eq "Fixed" -and $_.DriveLetter.ToString().Trim() -ne ""}
foreach ($Drive in $Drives) {
    if (Test-Path -Path "$($Drive.DriveLetter):\") {
        $EXEConfigFiles = Get-ChildItem "$($Drive.DriveLetter):\" -Filter "*.exe.config" -Recurse
    }
}
$MachineConfigFiles = @()
$MachineConfigFiles += Get-ChildItem "C:\Windows\Microsoft.NET\Framework\v4.0.30319" -Filter "machine.config" -Recurse
$MachineConfigFiles += Get-ChildItem "C:\Windows\Microsoft.NET\Framework64\v4.0.30319" -Filter "machine.config" -Recurse

return @{IsApplicable=$true; EXEConfigs = $EXEConfigFiles.FullName; MachineConfigs = $MachineConfigFiles.FullName}