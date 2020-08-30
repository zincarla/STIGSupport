Param($BeginData)
Write-Verbose "V-100283"

$Result = "NotAFinding"
$Details = ""
$Comments = ""


Import-Module WebAdministration;
$WebRoot = (Get-Item -PSPath "IIS:\Sites\$($BeginData.Site)").physicalPath

try{
    $Files = Get-ChildItem -Path ([System.Environment]::ExpandEnvironmentVariables($WebRoot)) -include @("*.bak", "*.old", "*.temp", "*.tmp", "*.backup", "copy of *") -Recurse -ErrorAction Stop
} catch {
    #Just in case permission related issue or something, we don't want to erroneosly mark this good
    $Result="Not_Reviewed"
    $Details+="Error occured querying Files`r`n"
}

if ($Webroot -ne $null)
{
    if ($Files.Length -gt 0) {
        foreach ($File in $Files)
        {
            $Result = "Open"
            $Details+=$File.FullName+"`r`n"
        }
    } else {
        $Details+= "No files found`r`n"
    }
} else {
    $Result="Not_Reviewed"
    $Details+="Web config could not be queried`r`n"
}

return @{Details=$Details;
            Comments=$Comments;
            Result=$Result}