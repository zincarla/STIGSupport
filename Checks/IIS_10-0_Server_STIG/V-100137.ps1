Write-Verbose "V-100137"
$Result = "NotAFinding"
$Details = ""
$Comments = ""

$Filter = @("*.java","*.jpp")
$Files=@()
$Drives = Get-Volume | Where-Object {$_.DriveType -eq "Fixed" -and $_.DriveLetter -ne $null}
foreach($Drive in $Drives) {
    Get-ChildItem -Path ($Drive.DriveLetter+":\*") -Include $Filter -Recurse | ForEach-Object -Process {$Files+=$_.FullName}
}

if ($Files -ne $null -and $Files.Count -eq 0)
{
    $Result = "NotAFinding"
}
else
{
    $Files | ForEach-Object -Process {$Details+="Found "+$_+"`r`n"}
    $Result="Open"
}

return @{Details=$Details;
            Comments=$Comments;
            Result=$Result}