Write-Verbose "V-76767"
$Result = "NotAFinding"
$Details = ""
$Comments = ""

if ((Test-Path -Path "Registry::HKEY_CLASSES_ROOT\CLSID\{0D43FE01-F093-11CF-8940-00A0C9054228}"))
{
    $Comments += "FSO Regkey was found "
} else {
    $Details+="FSO key does not exist "
}


return @{Details=$Details;
            Comments=$Comments;
            Result=$Result}