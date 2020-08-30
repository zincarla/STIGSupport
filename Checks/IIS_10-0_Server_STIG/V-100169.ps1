Write-Verbose "V-100169"
$Result = "Not_Reviewed"
$Details = ""
$Comments = ""

$Software = @()
$Software += Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall |
    Get-ItemProperty |
    Sort-Object -Property DisplayName |
    Select-Object -Property DisplayName, DisplayVersion |
    Where-Object -FilterScript {$_.DisplayName -ne "" -and $_.DisplayName -ne $null -and $_.DisplayName -notlike "Update for *" -and $_.DisplayName -notlike "Security Update for*"}
$Software += Get-ChildItem -Path HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall |
    Get-ItemProperty |
    Sort-Object -Property DisplayName |
    Select-Object -Property DisplayName, DisplayVersion |
    Where-Object -FilterScript {$_.DisplayName -ne "" -and $_.DisplayName -ne $null -and $_.DisplayName -notlike "Update for *" -and $_.DisplayName -notlike "Security Update for*"}

$Details = ($Software | Out-String) -replace '[^a-zA-Z0-9. ]',''

return @{Details=$Details;
            Comments=$Comments;
            Result=$Result}